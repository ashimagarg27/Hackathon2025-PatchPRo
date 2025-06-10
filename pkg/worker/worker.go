package worker

import (
	"log"
	"sync"
	"sync/atomic"

	"patchpro/pkg/models"
	"patchpro/utils"
)

const workers = 4

func Work(feed models.RawFeed, imageRepoMap map[string]string) {
	var issue atomic.Int64

	issue.Store(1000)

	jobs := make(chan *models.Job)

	// worker pool -----------------------------------------------------
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				key := job.Repo.URL // just for logging
				if err := Process(job); err != nil {
					log.Printf("[ERR] %s: %v", key, err)
					continue
				}

				log.Printf("[OK ] %s — %d modules", key, len(job.Modules))
			}
		}()
	}

	// producer: build Job objects -------------------------------------
	for key, entries := range feed {
		mapVal, ok := imageRepoMap[key]
		if !ok {
			log.Printf("[skip] %s: no repo mapping", key)
			continue
		}

		repoURL, branch := utils.SplitURL(mapVal)
		job, err := BuildJob(entries, repoURL, branch, int(issue.Load()))
		if err != nil {
			log.Printf("[skip] %s: %v", key, err)
			continue
		}
		if job == nil {
			log.Printf("[skip] %s: already up-to-date", key)
			continue
		}

		issue.Add(1)
		jobs <- job
	}

	close(jobs)
	wg.Wait()
}
