package proxyme

import (
	"fmt"
	"math/rand"
	"slices"
	"testing"
)

func FuzzLru_Add(f *testing.F) {
	// this fuzzer must run without parallels workers
	// go test -count=1 -parallel=1 -v -fuzz FuzzLru_Add proxyme
	size := 100
	cache := newCache[int, int](size)
	cnt := make(map[int]int)
	queue := make([]int, 0)
	values := make(map[int]int)

	f.Add(0, 0)
	f.Add(100000, 100000)
	f.Fuzz(func(t *testing.T, k int, v int) {
		values[k] = v
		cache.Add(k, v)
		cnt[k]++
		queue = append(queue, k)

		for len(cnt) > size {
			key := queue[0]
			cnt[key]--
			queue = queue[1:]

			if cnt[key] == 0 {
				delete(cnt, key)
			}
		}

		if len(cnt) != len(cache.list) {
			t.Error("invalid size node node")
		}

		for _, k := range queue {
			v, ok := cache.Get(k)
			if !ok {
				t.Errorf("no key %v fount in cache", k)
			}

			if v != values[k] {
				t.Errorf("invalid key %v value: %v", k, v)
			}
		}
	})
}

func FuzzLru_GetAdd(f *testing.F) {
	// this fuzzer must run without parallels workers
	// go test -count=1 -parallel=1 -v -fuzz FuzzLru_GetAdd proxyme
	size := 100
	cache := newCache[int, int](size)
	cnt := make(map[int]int)
	queue := make([]int, 0)
	values := make(map[int]int)

	f.Add(0, 0)
	f.Add(100000, 100000)
	f.Fuzz(func(t *testing.T, k int, v int) {
		// 50% operation GET
		if rand.Intn(100) < 50 {
			_, presented := cnt[k]
			if _, ok := cache.Get(k); ok != presented {
				t.Errorf("present key %v error %v should be %v", k, ok, presented)
			}

			if !presented {
				return
			}

			cnt[k]++
			queue = append(queue, k)

			return
		}

		// 50% operation ADD
		values[k] = v
		cache.Add(k, v)
		cnt[k]++
		queue = append(queue, k)

		for len(cnt) > size {
			key := queue[0]
			cnt[key]--
			queue = queue[1:]

			if cnt[key] == 0 {
				delete(cnt, key)
			}
		}

		if len(cnt) != len(cache.list) {
			t.Error("invalid size node node")
		}

		for _, k := range queue {
			v, ok := cache.Get(k)
			if !ok {
				t.Errorf("no key %v fount in cache", k)
			}

			if v != values[k] {
				t.Errorf("invalid key %v value: %v", k, v)
			}
		}
	})
}

func toFlatKeys[K comparable, V any](head *node[K, V]) ([]K, error) {
	curr := &node[K, V]{
		next: head,
	}

	// collect result
	result := make([]K, 0)
	for curr.next != nil {
		curr = curr.next
		result = append(result, curr.key)
	}

	// make sure that prev links are also correct
	index := len(result)
	for curr != nil {
		if index == 0 || result[index-1] != curr.key {
			return nil, fmt.Errorf("prev links are bad")
		}
		index--
		curr = curr.prev
	}
	if index != 0 {
		return nil, fmt.Errorf("prev links are bad")
	}

	return result, nil
}

func Test_lru_Add(t *testing.T) {

	type args[K comparable, V any] struct {
		k K
		v V
	}
	type testCase[K comparable, V any] struct {
		name   string
		size   int
		input  []V
		result [][]V
	}
	tests := []testCase[int, int]{
		{
			name:   "size 1 v1",
			size:   1,
			input:  []int{1, 1, 1, 1},
			result: [][]int{{1}, {1}, {1}, {1}},
		},
		{
			name:   "size 1 v2",
			size:   1,
			input:  []int{1, 1, 1, 2},
			result: [][]int{{1}, {1}, {1}, {2}},
		},
		{
			name:   "size 1 v3",
			size:   1,
			input:  []int{1, 1, 1, 2, 3},
			result: [][]int{{1}, {1}, {1}, {2}, {3}},
		},
		{
			name:   "size 1 v4",
			size:   1,
			input:  []int{1, 1, 1, 2, 3, 1},
			result: [][]int{{1}, {1}, {1}, {2}, {3}, {1}},
		},
		{
			name:   "size 1 v5",
			size:   1,
			input:  []int{1, 1, 1, 2, 2, 2, 1},
			result: [][]int{{1}, {1}, {1}, {2}, {2}, {2}, {1}},
		},
		{
			name:   "size 2 v2",
			size:   2,
			input:  []int{1, 1, 1, 1},
			result: [][]int{{1}, {1}, {1}, {1}},
		},
		{
			name:   "size 2 v3",
			size:   2,
			input:  []int{1, 2, 1, 2},
			result: [][]int{{1}, {1, 2}, {2, 1}, {1, 2}},
		},
		{
			name:   "size 2 v4",
			size:   2,
			input:  []int{1, 2, 2, 2},
			result: [][]int{{1}, {1, 2}, {1, 2}, {1, 2}},
		},
		{
			name:   "size 2 v5",
			size:   2,
			input:  []int{1, 1, 1, 2},
			result: [][]int{{1}, {1}, {1}, {1, 2}},
		},
		{
			name:   "size 2 v6",
			size:   2,
			input:  []int{1, 2, 3, 3, 2, 3, 1},
			result: [][]int{{1}, {1, 2}, {2, 3}, {2, 3}, {3, 2}, {2, 3}, {3, 1}},
		},
		{
			name:   "size 3 v1",
			size:   3,
			input:  []int{1, 2, 3, 1},
			result: [][]int{{1}, {1, 2}, {1, 2, 3}, {2, 3, 1}},
		},
		{
			name:   "size 3 v2",
			size:   3,
			input:  []int{1, 2, 3, 2},
			result: [][]int{{1}, {1, 2}, {1, 2, 3}, {1, 3, 2}},
		},
		{
			name:   "size 3 v3",
			size:   3,
			input:  []int{1, 2, 3, 3},
			result: [][]int{{1}, {1, 2}, {1, 2, 3}, {1, 2, 3}},
		},
		{
			name:   "size 3 v4",
			size:   3,
			input:  []int{1, 2, 3, 3, 1, 1, 3, 2, 1, 2, 2},
			result: [][]int{{1}, {1, 2}, {1, 2, 3}, {1, 2, 3}, {2, 3, 1}, {2, 3, 1}, {2, 1, 3}, {1, 3, 2}, {3, 2, 1}, {3, 1, 2}, {3, 1, 2}},
		},
		{
			name:   "size 3 v5",
			size:   3,
			input:  []int{1, 2, 3, 4, 1, 1, 3, 2, 1, 2, 5},
			result: [][]int{{1}, {1, 2}, {1, 2, 3}, {2, 3, 4}, {3, 4, 1}, {3, 4, 1}, {4, 1, 3}, {1, 3, 2}, {3, 2, 1}, {3, 1, 2}, {1, 2, 5}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := newCache[int, int](tt.size)
			for i, v := range tt.input {
				cache.Add(v, v)
				arr, err := toFlatKeys[int, int](cache.rear)
				if err != nil {
					t.Errorf("got error: %v", err)
					return
				}
				if !slices.Equal(tt.result[i], arr) {
					t.Errorf("invalid flat %v, want %v", arr, tt.result[i])
					return
				}
			}
		})
	}
}
