package vaultobjectscale

const (
	// TTLTimeUnit is the default number of seconds a TTL should be a multiple
	TTLTimeUnit int = 60
)

// RoundTTLToUnit takes an integer and rounds it to the nearest unit amount
func RoundTTLToUnit(TTL int, unit int) int {
	if TTL < 0 {
		return TTL
	}
	whole := TTL / unit
	remainder := TTL % unit
	roundedTTL := whole * unit
	if remainder > unit/2 {
		roundedTTL += unit
	}
	return roundedTTL
}

// CalcMaxTTL returns the lower TTL of 2 values
// There are 2 special values for the TTL. -1 and 0
// -1 represents an unlimited TTL
// 0 represents the default of a encompassing TTL or is the equilvalent of -1 when there is no encompassing TTL
func CalcMaxTTL(roleMaxTTL int, cfgMaxTTL int) int {
	return GetLowerTTL(roleMaxTTL, cfgMaxTTL)
}

// CalcTTL returns the calculated TTL from a requested TTL
// The requested TTL is limited by the TTL for a role, the TTL configured globally and an absolute maximum value
// There are 2 special values for the TTL. -1 and 0
// -1 represents an unlimited TTL
// 0 represents the default of a encompassing TTL or is the equilvalent of -1 when there is no encompassing TTL
func CalcTTL(requestedTTL int, roleTTL int, cfgTTL int, maxTTL int) int {
	if requestedTTL < 0 {
		return maxTTL
	} else if requestedTTL > 0 {
		return GetLowerTTL(requestedTTL, maxTTL)
	}
	// Return the default values as they cascade up
	if roleTTL != 0 {
		return GetLowerTTL(roleTTL, maxTTL)
	}
	if cfgTTL != 0 {
		return GetLowerTTL(cfgTTL, maxTTL)
	}
	return 0
}

// GetLowerTTL returns the larger TTL of 2 values
// There are 2 special values for the TTL. -1 and 0
// -1 represents an unlimited TTL
// 0 represents the default of a encompassing TTL or is the equilvalent of -1 when there is no encompassing TTL
func GetLowerTTL(lower int, upper int) int {
	switch {
	case upper <= 0 && lower <= 0:
		return -1
	case upper <= 0 && lower > 0:
		return lower
	case upper > 0 && lower <= 0:
		return upper
	case upper > 0 && lower > 0:
		if lower > upper {
			return upper
		}
		return lower
	}
	return 0
}
