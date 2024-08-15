package proxyme

import "sync"

type lru[K comparable, V any] struct {
	mu          sync.Mutex
	list        map[K]*list[K, V]
	front, rear *list[K, V]
	available   int
}

type list[K comparable, V any] struct {
	key        K
	value      V
	prev, next *list[K, V]
}

func newCache[K comparable, V any](size int) lru[K, V] {
	if size <= 0 {
		panic("invalid cache size")
	}

	return lru[K, V]{
		list:      make(map[K]*list[K, V]),
		available: size,
	}
}

func (c *lru[K, V]) Add(k K, v V) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// if cache is empty just newList
	if len(c.list) == 0 {
		c.newList(k, v)
		return
	}

	// key is presented in the cache
	l := c.list[k]
	if l != nil {
		c.toFront(l, v)
		return
	}

	// new key/value
	c.add(k, v)
}

// Get returns value from cache, if not exists return false
func (c *lru[K, V]) Get(k K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	l := c.list[k]
	if l == nil {
		return *new(V), false
	}

	c.toFront(l, l.value)
	return l.value, true
}

// add adds **new** key/value to **non empty** cache
func (c *lru[K, V]) add(k K, v V) {
	if len(c.list) == 0 {
		panic("cache must be non empty")
	}

	// simple add to the front
	item := &list[K, V]{
		key:   k,
		value: v,
	}
	c.list[k] = item
	c.front.next, item.prev = item, c.front
	c.front = item

	// if queue is not full
	if c.available > 0 {
		c.available--
		return
	}

	// evicted evict last recently use
	delete(c.list, c.rear.key)
	c.rear = c.rear.next
}

// toFront moves existing elem to the front & updates new value
func (c *lru[K, V]) toFront(l *list[K, V], newValue V) {
	if len(c.list) == 0 {
		panic("cache must be non empty")
	}

	// update value
	l.value = newValue

	// if it is already in front
	if l.next == nil {
		return
	}

	// update rear
	if l == c.rear {
		c.rear = l.next
	}

	prev, next := l.prev, l.next
	l.prev, l.next = c.front, nil
	c.front.next = l
	c.front = l
	next.prev = prev
	if prev != nil {
		prev.next = next
	}
}

func (c *lru[K, V]) newList(k K, v V) {
	list := &list[K, V]{
		key:   k,
		value: v,
	}
	c.front = list
	c.rear = list
	c.list[k] = list
	c.available--
}
