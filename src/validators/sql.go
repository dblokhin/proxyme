// 26.04.18 proxyme
// Proxyme Developers. All rights reserved.
// License can be found in the LICENSE file.

package validators

import (
	"github.com/dblokhin/dbwrapper"
	"log"
)

type SQL struct {
	db dbwrapper.DB
	query string
}

// NewSQLValidator returns *SQL login/pass validator. Its return true if
// sqlMatchString query returns exactly 1 row.
// sqlMatchString MUST query with given login/pass like this:
// 		sqlMatchString = `SELECT id FROM users WHERE user = ? and pass = ?`
// You can variate with your database functions:
//		sqlMatchString = `SELECT no_matter_here FROM users WHERE user = ? and pass = sha256(?)`
func NewSQLValidator(driver, source, sqlMatchString string) (*SQL, error) {
	db, err := dbwrapper.New(driver, source, "")
	if err != nil {
		return nil, err
	}

	return &SQL{
		db: db,
		query: sqlMatchString,
	}, nil
}

// Authorize checks auth with login/pass
func (s *SQL) Authorize(login, pass string) bool {
	res, err := s.db.Query(s.query, login, pass)
	if err != nil {
		log.Println(err)
		return false
	}

	// returns true if query matched exactly 1 row
	return len(res) == 1
}
