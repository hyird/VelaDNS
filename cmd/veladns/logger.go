package main

import (
	"log"
)

type logger struct {
	threshold int
}

func newLogger(level string) *logger {
	threshold := 2
	switch level {
	case "debug":
		threshold = 0
	case "info":
		threshold = 1
	case "warn":
		threshold = 2
	case "error":
		threshold = 3
	}
	return &logger{threshold: threshold}
}

func (l *logger) infof(format string, args ...any) {
	if l.threshold <= 1 {
		log.Printf("[VelaDNS] INFO "+format, args...)
	}
}

func (l *logger) warnf(format string, args ...any) {
	if l.threshold <= 2 {
		log.Printf("[VelaDNS] WARN "+format, args...)
	}
}

func (l *logger) errorf(format string, args ...any) {
	log.Printf("[VelaDNS] ERROR "+format, args...)
}
