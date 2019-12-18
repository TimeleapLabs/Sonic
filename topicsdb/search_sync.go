package topicsdb

import (
	"github.com/ethereum/go-ethereum/core/types"
)

func (tt *Index) fetchSync(cc ...Condition) (res []*types.Log, err error) {
	if len(cc) > MaxCount {
		err = ErrTooManyTopics
		return
	}

	recs := make(map[ID]*logrecBuilder)

	conditions := uint8(len(cc))
	for _, cond := range cc {
		for _, alternative := range cond {
			it := tt.table.Topic.NewIteratorWithPrefix(alternative[:])
			for it.Next() {
				id := extractLogrecID(it.Key())
				topicCount := bytesToPos(it.Value())
				rec := recs[id]
				if rec == nil {
					rec = newLogrecBuilder(id, conditions, topicCount)
					recs[id] = rec
				}
				rec.MatchedWith(cond)
			}

			err = it.Error()
			if err != nil {
				return
			}

			it.Release()
		}
	}

	for _, rec := range recs {
		if !rec.IsMatched() {
			continue
		}

		err = rec.Fetch(tt.table.Other, tt.table.Logrec)
		if err != nil {
			return
		}

		var r *types.Log
		r, err = rec.Build()
		if err != nil {
			return
		}
		res = append(res, r)
	}

	return
}