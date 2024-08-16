package proxyme

import "sync"

// syncLRU represents a concurrent-safe Least Recently Used (LRU) cache.
type syncLRU[K comparable, V any] struct {
	mu    sync.RWMutex
	cache *lru[K, V]
}

// newSyncCache returns a new instance of a concurrent-safe LRU cache.
func newSyncCache[K comparable, V any](size int) *syncLRU[K, V] {
	return &syncLRU[K, V]{
		cache: newCache[K, V](size),
	}
}

// Add inserts/updates a key-value pair in the cache.
func (c *syncLRU[K, V]) Add(k K, v V) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache.Add(k, v)
}

// Get retrieves a value from the cache. If the key doesn't exist, it returns the zero value for V and false.
func (c *syncLRU[K, V]) Get(k K) (V, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.cache.Get(k)
}

// lru represents a generic Least Recently Used (LRU) cache.
// Implementation allows efficient O(1) access and updates to the cache
// with constant-time eviction of the least recently used elements.
type lru[K comparable, V any] struct {
	list        map[K]*node[K, V]
	front, rear *node[K, V]
	available   int
}

// node represents a node in the doubly linked list used by the cache.
type node[K comparable, V any] struct {
	key        K
	value      V
	prev, next *node[K, V]
}

// newCache returns new instance lru cache with size > 0
func newCache[K comparable, V any](size int) *lru[K, V] {
	if size <= 0 {
		panic("invalid cache size")
	}

	return &lru[K, V]{
		list:      make(map[K]*node[K, V]),
		available: size,
	}
}

// Add inserts/updates if exists key value pair to the cache
func (c *lru[K, V]) Add(k K, v V) {
	// if cache is empty just newList
	if len(c.list) == 0 {
		c.newList(k, v)
		return
	}

	// key is presented in the cache
	l := c.list[k]
	if l != nil {
		// update value
		l.value = v
		c.toFront(l)
		return
	}

	// new key/value
	c.add(k, v)
}

// Get retrieves a value from the cache. If the key doesn't exist, it returns false.
func (c *lru[K, V]) Get(k K) (V, bool) {
	l := c.list[k]
	if l == nil {
		return *new(V), false
	}

	c.toFront(l)
	return l.value, true
}

// add adds **new** key/value to **non empty** cache
func (c *lru[K, V]) add(k K, v V) {
	if len(c.list) == 0 {
		panic("cache must be non empty")
	}

	// simple add to the front
	item := &node[K, V]{
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

	// evict least recently use
	delete(c.list, c.rear.key)
	c.rear = c.rear.next
}

// toFront moves existing elem to the front & updates new value
func (c *lru[K, V]) toFront(l *node[K, V]) {
	if len(c.list) == 0 {
		panic("cache must be non empty")
	}

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
	list := &node[K, V]{
		key:   k,
		value: v,
	}
	c.front = list
	c.rear = list
	c.list[k] = list
	c.available--
}
