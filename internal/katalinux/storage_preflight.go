package katalinux

import "errors"

var (
	ErrStorageForeignOwner   = errors.New("execution storage belongs to another journal; configure storage dedicated to this journal")
	ErrStorageJournalBinding = errors.New("execution storage has a legacy owner without a journal ID; use dedicated storage for new admissions")
	ErrStorageIndex          = errors.New("execution storage allocation index or ownership record is invalid; preserve it for recovery")
	ErrStorageFilesystem     = errors.New("execution storage backing filesystem differs from the signed profile")
)
