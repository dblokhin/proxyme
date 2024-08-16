package proxyme

import (
	"math/rand"
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
