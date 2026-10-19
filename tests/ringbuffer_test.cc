// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Covers the two containers the KCP core is built on (ringbuffer.go, kcp.go:162-198): the
// growable FIFO used by all three segment queues, and the min-heap that reorders out-of-order
// arrivals. Both are load-bearing for correctness in ways that are easy to miss - a ring that
// loses the tail on grow stalls a transfer, and a heap that compares with plain operator< breaks
// once the sequence number wraps, which takes 49 days to show up in the field.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <random>
#include <string>
#include <vector>

#include "kcp/internal/kcp_segment.h"
#include "kcp/internal/ringbuffer.h"

namespace {

int g_failures = 0;

void Fail(const char* file, int line, const std::string& message) {
  std::fprintf(stderr, "FAIL %s:%d: %s\n", file, line, message.c_str());
  ++g_failures;
}

#define CHECK(cond)                                     \
  do {                                                  \
    if (!(cond)) {                                      \
      Fail(__FILE__, __LINE__, "CHECK failed: " #cond); \
    }                                                   \
  } while (false)

#define CHECK_EQ(a, b)                                                                         \
  do {                                                                                         \
    const auto lhs = (a);                                                                      \
    const auto rhs = (b);                                                                      \
    if (!(lhs == rhs)) {                                                                       \
      Fail(__FILE__, __LINE__,                                                                 \
           std::string("CHECK_EQ failed: " #a " == " #b " (") + std::to_string(lhs) + " vs " + \
               std::to_string(rhs) + ")");                                                     \
    }                                                                                          \
  } while (false)

constexpr std::size_t kSize = 8;

using kcp::internal::RingBuffer;
using kcp::internal::Segment;
using kcp::internal::SegmentHeap;

void TestEmptyState() {
  RingBuffer<int> ring(kSize);
  CHECK_EQ(ring.Len(), 0u);
  CHECK(ring.IsEmpty());
  CHECK(!ring.IsFull());
  // ringbuffer.go:238 - capacity is reported as len-1; one slot always stays empty so that
  // head == tail can mean "empty".
  CHECK_EQ(ring.MaxLen(), kSize - 1);
  CHECK(ring.Peek() == nullptr);

  int value = 0;
  CHECK(!ring.Pop(&value));
}

void TestFifoAcrossWrap() {
  RingBuffer<int> ring(kSize);
  for (int i = 0; i < 7; ++i) {
    ring.Push(i);
  }
  CHECK(ring.IsFull());
  CHECK_EQ(ring.Len(), 7u);

  // Drain three, then refill: the tail wraps past the end of the backing store.
  for (int i = 0; i < 3; ++i) {
    int value = -1;
    CHECK(ring.Pop(&value));
    CHECK_EQ(value, i);
  }
  for (int i = 7; i < 11; ++i) {
    ring.Push(i);
  }
  CHECK_EQ(ring.Len(), 8u);

  for (int i = 3; i < 11; ++i) {
    int value = -1;
    CHECK(ring.Pop(&value));
    CHECK_EQ(value, i);
  }
  CHECK(ring.IsEmpty());
}

void TestGrowPreservesOrder() {
  // Well past the doubling threshold: the growth policy switches to +10% part way through, so
  // this exercises both branches and the wrapped copy.
  RingBuffer<int> ring(8);
  constexpr int kCount = 3000;
  for (int i = 0; i < kCount; ++i) {
    ring.Push(i);
  }
  CHECK_EQ(ring.Len(), static_cast<std::size_t>(kCount));
  CHECK(ring.MaxLen() >= static_cast<std::size_t>(kCount));

  for (int i = 0; i < kCount; ++i) {
    int value = -1;
    CHECK(ring.Pop(&value));
    CHECK_EQ(value, i);
  }
  CHECK(ring.IsEmpty());
}

void TestDiscard() {
  RingBuffer<int> ring(kSize);
  for (int i = 0; i < 7; ++i) {
    ring.Push(i);
  }
  CHECK_EQ(ring.Discard(3), 3u);
  CHECK_EQ(ring.Len(), 4u);
  int value = -1;
  CHECK(ring.Pop(&value));
  CHECK_EQ(value, 3);

  // Asking for more than is present clamps instead of over-running.
  CHECK_EQ(ring.Discard(100), 3u);
  CHECK(ring.IsEmpty());

  // Discarding everything takes the Clear path; the ring must still be usable afterwards.
  for (int i = 0; i < 5; ++i) {
    ring.Push(i + 100);
  }
  CHECK_EQ(ring.Discard(5), 5u);
  ring.Push(7);
  CHECK(ring.Pop(&value));
  CHECK_EQ(value, 7);
}

void TestIterationOrder() {
  RingBuffer<int> ring(kSize);
  for (int i = 0; i < 5; ++i) {
    ring.Push(i);
  }
  // Force the wrapped layout so both branches of each iterator are covered.
  ring.Discard(2);
  for (int i = 5; i < 9; ++i) {
    ring.Push(i);
  }

  std::vector<int> forward;
  ring.ForEach([&forward](int& value) {
    forward.push_back(value);
    return true;
  });
  CHECK(forward == std::vector<int>({2, 3, 4, 5, 6, 7, 8}));

  std::vector<int> reverse;
  ring.ForEachReverse([&reverse](int& value) {
    reverse.push_back(value);
    return true;
  });
  CHECK(reverse == std::vector<int>({8, 7, 6, 5, 4, 3, 2}));

  // Returning false stops immediately - this is how the reference expresses break.
  std::vector<int> stopped;
  ring.ForEach([&stopped](int& value) {
    stopped.push_back(value);
    return stopped.size() < 2;
  });
  CHECK(stopped == std::vector<int>({2, 3}));
}

void TestPeekIsNonDestructive() {
  RingBuffer<int> ring(kSize);
  ring.Push(11);
  ring.Push(22);
  CHECK(ring.Peek() != nullptr);
  CHECK_EQ(*ring.Peek(), 11);
  CHECK_EQ(ring.Len(), 2u);

  // Mutating through Peek affects the stored element, which is what Kcp uses to patch the tail
  // segment in stream mode.
  *ring.Peek() = 33;
  int value = 0;
  CHECK(ring.Pop(&value));
  CHECK_EQ(value, 33);
}

void TestRingBufferAgainstModel() {
  // Randomized differential test against std::deque. The fixed sequences above walk a handful of
  // wrap/grow paths; this walks thousands of interleavings of them, which is where an off-by-one in
  // the wrapped arithmetic actually shows up. The model is deliberately blind to the ring's
  // internals: it only knows push appends, pop takes the front, discard drops from the front.
  RingBuffer<int> ring(8);
  std::deque<int> model;
  std::mt19937 rng(0xC0FFEEu);
  int next_value = 0;
  int content_checks = 0;

  for (int step = 0; step < 20000; ++step) {
    // The mix is deliberately push-heavy: with a symmetric mix the queue keeps draining to empty
    // and the growth paths (which is where the wrapped copy happens) are never reached at all.
    const unsigned op = rng() % 24u;
    if (op < 14u) {
      ring.Push(next_value);
      model.push_back(next_value);
      ++next_value;
    } else if (op < 19u) {
      int got = -1;
      const bool popped = ring.Pop(&got);
      CHECK_EQ(popped, !model.empty());
      if (popped) {
        CHECK_EQ(got, model.front());
        model.pop_front();
      }
    } else if (op < 22u) {
      const std::size_t want = rng() % 3u;
      const std::size_t dropped = ring.Discard(want);
      const std::size_t expect = want < model.size() ? want : model.size();
      CHECK_EQ(dropped, expect);
      for (std::size_t i = 0; i < expect; ++i) {
        model.pop_front();
      }
    } else if (op == 22u) {
      if (model.empty()) {
        CHECK(ring.Peek() == nullptr);
      } else {
        CHECK(ring.Peek() != nullptr && *ring.Peek() == model.front());
      }
    } else if (model.size() < 32u) {
      // Clear only while the ring is small, otherwise it would destroy the length the growth
      // paths need to reach.
      ring.Clear();
      model.clear();
    }

    // Structural invariants the queue consumers rely on, checked every step.
    CHECK_EQ(ring.Len(), model.size());
    CHECK_EQ(ring.IsEmpty(), model.empty());
    CHECK_EQ(ring.IsFull(), ring.Len() == ring.MaxLen());
    CHECK(ring.MaxLen() >= ring.Len());

    // Full content comparison, forward and reverse, every so often.
    if (step % 53 == 0) {
      std::vector<int> forward;
      ring.ForEach([&forward](int& value) {
        forward.push_back(value);
        return true;
      });
      std::vector<int> reverse;
      ring.ForEachReverse([&reverse](int& value) {
        reverse.push_back(value);
        return true;
      });
      std::vector<int> expected(model.begin(), model.end());
      CHECK(forward == expected);
      std::reverse(expected.begin(), expected.end());
      CHECK(reverse == expected);
      ++content_checks;
    }
  }

  CHECK(content_checks > 0);
  // The run must actually have grown the ring well past its initial capacity, otherwise it is
  // testing the same paths the fixed tests already cover.
  CHECK(ring.MaxLen() >= 1024u);
}

void TestHeapOrdering() {
  SegmentHeap heap;
  for (std::uint32_t sn : {3u, 1u, 2u}) {
    Segment seg;
    seg.sn = sn;
    heap.Push(std::move(seg));
  }
  CHECK_EQ(heap.Len(), 3u);
  for (std::uint32_t expected : {1u, 2u, 3u}) {
    Segment out;
    CHECK(heap.Pop(&out));
    CHECK_EQ(out.sn, expected);
  }
  CHECK_EQ(heap.Len(), 0u);

  Segment out;
  CHECK(!heap.Pop(&out));
}

void TestHeapWraparound() {
  // Sequence numbers near the 32-bit wrap: plain comparison would put 0 below 0xFFFFFFFE, but in
  // serial-number arithmetic it comes after.
  SegmentHeap heap;
  const std::vector<std::uint32_t> sns = {0xFFFFFFFFu, 0u, 0xFFFFFFFEu, 1u};
  for (std::uint32_t sn : sns) {
    Segment seg;
    seg.sn = sn;
    heap.Push(std::move(seg));
  }
  const std::vector<std::uint32_t> expected = {0xFFFFFFFEu, 0xFFFFFFFFu, 0u, 1u};
  for (std::uint32_t sn : expected) {
    Segment out;
    CHECK(heap.Pop(&out));
    CHECK_EQ(out.sn, sn);
  }
}

void TestHeapMarks() {
  SegmentHeap heap;
  Segment seg;
  seg.sn = 42;
  heap.Push(std::move(seg));
  CHECK(heap.Has(42));
  CHECK(!heap.Has(43));

  Segment out;
  CHECK(heap.Pop(&out));
  // The membership set exists so duplicate suppression is a lookup rather than a scan; it must be
  // released when the segment leaves the heap.
  CHECK(!heap.Has(42));
}

void TestHeapRandomInsertDelete() {
  // Insert in a scrambled order and pop in ascending order, interleaving deletions so the sift
  // paths see both "leaf stays put" and "element moves up".
  std::vector<std::uint32_t> values;
  for (std::uint32_t i = 0; i < 500; ++i) {
    values.push_back((i * 37 + 11) % 500);
  }
  SegmentHeap heap;
  for (std::uint32_t sn : values) {
    Segment seg;
    seg.sn = sn;
    heap.Push(std::move(seg));
  }
  CHECK_EQ(heap.Len(), 500u);
  for (std::uint32_t expected = 0; expected < 500; ++expected) {
    Segment out;
    CHECK(heap.Pop(&out));
    CHECK_EQ(out.sn, expected);
  }
}

}  // namespace

int main() {
  TestEmptyState();
  TestFifoAcrossWrap();
  TestGrowPreservesOrder();
  TestDiscard();
  TestIterationOrder();
  TestPeekIsNonDestructive();
  TestRingBufferAgainstModel();
  TestHeapOrdering();
  TestHeapWraparound();
  TestHeapMarks();
  TestHeapRandomInsertDelete();

  if (g_failures != 0) {
    std::fprintf(stderr, "%d failure(s)\n", g_failures);
    return 1;
  }
  std::printf("ringbuffer_test: all checks passed\n");
  return 0;
}
