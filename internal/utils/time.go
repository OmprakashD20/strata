package utils

import (
	"fmt"
	"time"
)

func FormatTimezoneOffset(t time.Time) string {
	_, offsetSecs := t.Zone()
	sign := "+"
	if offsetSecs < 0 {
		sign = "-"
		offsetSecs = -offsetSecs
	}
	hours := offsetSecs / 3600
	minutes := (offsetSecs % 3600) / 60
	return fmt.Sprintf("%s%02d%02d", sign, hours, minutes)
}
