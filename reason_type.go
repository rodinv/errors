package errors

const (
	ReasonInternal     ReasonType = iota // Internal error, the default setting.
	ReasonNotFound                       // Thing you are looking for is missing.
	ReasonBadRequest                     // Error due to invalid request.
	ReasonAccessDenied                   // Error due to lack of rights
)

// ReasonType indicates the reason for the error.
type ReasonType uint8

// Internal returns a builder that forcibly
// overwrites the error reason type with
// ReasonInternal.
func Internal() Builder {
	return global.Internal()
}
func (b Builder) Internal() Builder {
	b.OverwriteReason = true
	b.ReasonType = ReasonInternal
	return b
}

// NotFound returns a builder that forcibly
// overwrites the error reason type with
// ReasonNotFound.
func NotFound() Builder {
	return global.NotFound()
}
func (b Builder) NotFound() Builder {
	b.ReasonType = ReasonNotFound
	b.OverwriteReason = true
	return b
}

// BadRequest returns a builder that forcibly
// overwrites the error reason type with
// ReasonBadRequest.
func BadRequest() Builder {
	return global.BadRequest()
}
func (b Builder) BadRequest() Builder {
	b.ReasonType = ReasonBadRequest
	b.OverwriteReason = true
	return b
}

// AccessDenied returns a builder that forcibly
// overwrites the error reason type with
// ReasonAccessDenied.
func AccessDenied() Builder {
	return global.AccessDenied()
}
func (b Builder) AccessDenied() Builder {
	b.ReasonType = ReasonAccessDenied
	b.OverwriteReason = true
	return b
}

// CauseAccessDenied identifies the cause of the error lack of rights.
func CauseAccessDenied(err error) error {
	return global.WithSkip(1).CauseAccessDenied(err)
}
func (b Builder) CauseAccessDenied(err error) error {
	return b.withReasonType(err, ReasonAccessDenied)
}

// CauseBadRequest identifies the cause of the error invalid request.
func CauseBadRequest(err error) error {
	return global.WithSkip(1).CauseBadRequest(err)
}
func (b Builder) CauseBadRequest(err error) error {
	return b.withReasonType(err, ReasonBadRequest)
}

// CauseNotFound identifies the cause of the error required thing is missing.
func CauseNotFound(err error) error {
	return global.WithSkip(1).CauseNotFound(err)
}
func (b Builder) CauseNotFound(err error) error {
	return b.withReasonType(err, ReasonNotFound)
}

// withReasonType sets rt to err.
func (b Builder) withReasonType(err error, rt ReasonType) error {
	r := b.extractFrom(err)
	if r == nil {
		return nil
	}

	r.ReasonType = rt
	if len(r.callers) == 0 {
		r.callers = b.WithSkip(1).CallersIfNeed()
	}

	return r
}
