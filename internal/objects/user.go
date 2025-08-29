package objects

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type User struct {
	Info      string // <name> <email>
	Timestamp int64  // unix timestamp
	TZ        string // time zone of the user
}

func (u *User) String() string {
	if u == nil {
		return "User{nil}"
	}

	return fmt.Sprintf("%s %d %s", u.Info, u.Timestamp, u.TZ)
}

func validateUser(user *User) error {
	if user == nil {
		return fmt.Errorf("user required")
	}
	pattern := `^[A-Za-z\s]+ <[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}>$`
	re := regexp.MustCompile(pattern)

	if user.Info == "" {
		return fmt.Errorf("user info required")
	}
	if !re.MatchString(user.Info) {
		return fmt.Errorf("user info must match the format: name <email>")
	}
	if user.Timestamp == 0 {
		return fmt.Errorf("user timestamp required")
	}
	if user.TZ == "" {
		return fmt.Errorf("user timezone required")
	}

	return nil
}

// Extracts the user info and timestamp from the serialized content
func parseUser(line string) (*User, error) {
	parts := strings.Fields(line)

	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid user: %s", line)
	}

	ts, err := strconv.ParseInt(parts[len(parts)-2], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid timestamp in user: %v", err)
	}

	tz := parts[len(parts)-1]
	info := strings.Join(parts[:len(parts)-2], " ")

	return &User{
		Info:      info,
		Timestamp: ts,
		TZ:        tz,
	}, nil
}
