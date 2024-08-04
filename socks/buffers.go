// 15.04.18 proxyme
// Proxyme Developers. All rights reserved.
// License can be found in the LICENSE file.

package socks

// it's just impl reusable buffers

const (
	// buff size from client to remote
	clientBufferSize int = 2 * 1024
	// buff size to client from remote
	hostBufferSize = 32 * 1024
)

var (
	clientBuff, hostBuff reBuffer
)

// reBuffer allows reuse buffers
type reBuffer struct {
	// buffered queue of buffers
	queue chan []byte

	// size counter of allocates
	size int
	// maxSize maximum of new allocates
	maxSize int

	// buffSize size of buffers in queue
	buffSize int
}

// Get returns reusable buffer
func (rb *reBuffer) Get() []byte {

	select {
	case buff := <-rb.queue:
		return buff

	default:
		// if threshold is not reached
		if rb.size < rb.maxSize {
			rb.size++
			return make([]byte, rb.buffSize)
		}

		// block
		return <-rb.queue
	}

	// never reach
	return nil
}

// Put putting buff for reusable purposes
func (rb *reBuffer) Put(b []byte) {
	select {
	case rb.queue <- b: // Try to put back into the pool
	default: // Pool is full, will be garbage collected
		rb.size--
	}
}

func init() {
	clientBuff = reBuffer{
		queue:    make(chan []byte, 100),
		size:     0,
		maxSize:  100,
		buffSize: clientBufferSize,
	}

	hostBuff = reBuffer{
		queue:    make(chan []byte, 100),
		size:     0,
		maxSize:  100,
		buffSize: hostBufferSize,
	}
}
