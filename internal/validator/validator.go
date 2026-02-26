package validator

import (
	"fmt"
	"strconv"
	"strings"
)

// FieldError contains a validation error for one field.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// Errors is a collection of validation issues.
type Errors struct {
	Items []FieldError `json:"errors"`
}

func (e *Errors) Error() string {
	return "validation failed"
}

// Add appends a field error.
func (e *Errors) Add(field, message string) {
	e.Items = append(e.Items, FieldError{Field: field, Message: message})
}

// HasAny returns true if there are validation issues.
func (e *Errors) HasAny() bool {
	return len(e.Items) > 0
}

// ValidateRequiredString validates that a string value exists after trim.
func ValidateRequiredString(errs *Errors, field, value string) {
	if strings.TrimSpace(value) == "" {
		errs.Add(field, "required")
	}
}

// ParsePositiveUint parses and validates a positive integer identifier.
func ParsePositiveUint(raw, field string) (uint, error) {
	v, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
	if err != nil || v == 0 {
		verr := &Errors{}
		verr.Add(field, "must be a positive integer")
		return 0, verr
	}
	return uint(v), nil
}

// ParsePagination parses and bounds pagination query values.
func ParsePagination(pageRaw, limitRaw string, defaultLimit, maxLimit int) (int, int, error) {
	errs := &Errors{}
	page := 1
	limit := defaultLimit

	if strings.TrimSpace(pageRaw) != "" {
		v, err := strconv.Atoi(pageRaw)
		if err != nil || v < 1 {
			errs.Add("page", "must be a positive integer")
		} else {
			page = v
		}
	}
	if strings.TrimSpace(limitRaw) != "" {
		v, err := strconv.Atoi(limitRaw)
		if err != nil || v < 1 {
			errs.Add("limit", "must be a positive integer")
		} else if v > maxLimit {
			errs.Add("limit", fmt.Sprintf("must be <= %d", maxLimit))
		} else {
			limit = v
		}
	}
	if errs.HasAny() {
		return 0, 0, errs
	}
	return page, limit, nil
}
