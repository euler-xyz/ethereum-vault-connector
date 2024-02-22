// CER-32: Execution Context MUST keep track of whether the Checks are deferred
// with a boolean flag. The flag MUST be set  when a Checks-deferrable Call
// starts and MUST be cleared at the end of it, but only when the flag was not
// set before the call.
