package proxyme

import (
	"testing"
)

func FuzzLru_Add(f *testing.F) {
	// this fuzzer must run without parallels workers
	// go test -count=1 -parallel=1 -v -fuzz FuzzLru_Add proxyme
	size := 100
	cache := newCache[int, int](size)
	cnt := make(map[int]int)
	queue := make([]int, 0)

	f.Add(0, 0)
	f.Add(100000, 100000)
	f.Fuzz(func(t *testing.T, k int, v int) {
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
			t.Error("invalid size list list")
		}

		for _, k := range queue {
			if _, ok := cache.Get(k); !ok {
				t.Errorf("no key %v fount in cache", k)
			}
		}
	})
}
