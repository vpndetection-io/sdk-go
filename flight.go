package vpndetection

import (
	"context"
	"sync"
)

// flights is the board of addresses with a request in flight, so concurrent
// misses share one. A flight is keyed as the cache is, on the address and the
// user agent sent with it, so only misses for the same pair share a request. A cache that checks, misses and then fetches let every
// caller missing in the same moment fetch too: a middleware answering several
// requests from one visitor at once paid for the same lookup several times.
//
// It is ours rather than golang.org/x/sync/singleflight because a batch has to
// know which addresses it leads before it builds its chunks, and singleflight
// decides that inside DoChan and runs the function on a goroutine of its own.
type flights struct {
	mu sync.Mutex
	m  map[answerKey]*flight
}

// flight is one address's request. Every caller awaiting it reads the answer
// once done is closed.
type flight struct {
	done   chan struct{}
	result *Result
	err    error
	// The callers awaiting it and the request carrying it, guarded by
	// flights.mu.
	waiters int
	sender  *sender
}

// sender is one request sent for the flights it leads: a Lookup's own, or one
// chunk of a batch. It runs detached from every caller, so a caller giving up
// cannot stop it, and one asleep on a long Retry-After would hold every later
// caller for the address as long. It gives up on that sleep, and only that,
// once no caller awaits any of its flights.
type sender struct {
	board   *flights
	keys    []answerKey
	flights []*flight
	waiting int
	resting bool
	cancel  context.CancelFunc
}

type senderKey struct{}

// board joins the flight for each address that has one and starts one for each
// that has none, which the caller then sends and lands. The caller is counted
// as awaiting each, until it leaves.
func (f *flights) board(keys []answerKey) (led, joined map[answerKey]*flight) {
	led = make(map[answerKey]*flight, len(keys))
	joined = make(map[answerKey]*flight)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.m == nil {
		f.m = make(map[answerKey]*flight)
	}
	for _, key := range keys {
		if fl, ok := f.m[key]; ok {
			fl.join()
			joined[key] = fl
			continue
		}
		fl := &flight{done: make(chan struct{}), waiters: 1}
		f.m[key] = fl
		led[key] = fl
	}
	return led, joined
}

func (fl *flight) join() {
	fl.waiters++
	if fl.sender != nil {
		fl.sender.waiting++
	}
}

// send makes one request of the led flights for keys, and answers the context
// to run it under: ctx with a sender whose backoff waits can be given up on.
// The caller cancels it, whatever the outcome, once the request has landed.
func (f *flights) send(
	ctx context.Context, led map[answerKey]*flight, keys []answerKey,
) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)
	s := &sender{board: f, keys: keys, flights: make([]*flight, len(keys)), cancel: cancel}
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, key := range keys {
		fl := led[key]
		fl.sender = s
		s.flights[i] = fl
		s.waiting += fl.waiters
	}
	return context.WithValue(ctx, senderKey{}, s), cancel
}

// leave takes a caller that gave up off the flights it awaited, and a sender
// left with nobody awaiting it stops waiting.
func (f *flights) leave(awaited ...*flight) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, fl := range awaited {
		fl.waiters--
		if s := fl.sender; s != nil {
			s.waiting--
			s.giveUpIfIdle()
		}
	}
}

// rest marks the sender as asleep in a backoff until the returned function is
// called, and gives that sleep up at once when nobody awaits it.
func (s *sender) rest() func() {
	s.board.mu.Lock()
	defer s.board.mu.Unlock()
	s.resting = true
	s.giveUpIfIdle()
	return func() {
		s.board.mu.Lock()
		defer s.board.mu.Unlock()
		s.resting = false
	}
}

// giveUpIfIdle cancels a sleeping sender nobody awaits and takes its flights
// off the board, so a caller arriving next leads a request of its own rather
// than joining one that is stopping. A request under way is left to finish and
// be cached. Called with the board's lock held.
func (s *sender) giveUpIfIdle() {
	if !s.resting || s.waiting > 0 {
		return
	}
	for i, key := range s.keys {
		if s.board.m[key] == s.flights[i] {
			delete(s.board.m, key)
		}
	}
	s.cancel()
}

// land hands every waiter the answer and takes the address off the board. Cache
// a served answer FIRST: a caller that missed the cache just before it landed
// finds no flight after this, and reads the cache again before it sends.
func (f *flights) land(key answerKey, fl *flight, result *Result, err error) {
	f.mu.Lock()
	if f.m[key] == fl {
		delete(f.m, key)
	}
	f.mu.Unlock()
	fl.result, fl.err = result, err
	close(fl.done)
}

// answer is the landed outcome as one caller's own, a copy of the result as a
// cache hit is.
func (fl *flight) answer() (*Result, error) {
	if fl.err != nil {
		return nil, fl.err
	}
	result := *fl.result
	return &result, nil
}
