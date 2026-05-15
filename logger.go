package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

const AppVersion = "2.0.0"

type LogLevel int

const (
	LogDEBUG LogLevel = iota
	LogINFO
	LogWARN
	LogERROR
	LogFATAL
)

var levelNames = map[LogLevel]string{
	LogDEBUG: "DEBUG",
	LogINFO:  "INFO ",
	LogWARN:  "WARN ",
	LogERROR: "ERROR",
	LogFATAL: "FATAL",
}

// ANSI colors for console output
var levelColors = map[LogLevel]string{
	LogDEBUG: "\033[36m",  // cyan
	LogINFO:  "\033[32m",  // green
	LogWARN:  "\033[33m",  // yellow
	LogERROR: "\033[31m",  // red
	LogFATAL: "\033[35m",  // magenta
}

const colorReset = "\033[0m"

type Logger struct {
	mu       sync.Mutex
	file     *os.File
	level    LogLevel
	logPath  string
	console  bool // also print to stdout
}

var Log *Logger

func InitLogger(path string, level LogLevel, console bool) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %v", err)
	}
	Log = &Logger{
		file:    f,
		level:   level,
		logPath: path,
		console: console,
	}
	Log.Info("=== MemHacker v%s started ===", AppVersion)
	Log.Info("Log file: %s", path)
	Log.Info("Log level: %s", levelNames[level])
	return nil
}

func (l *Logger) Close() {
	if l.file != nil {
		l.Info("=== MemHacker shutting down ===")
		l.file.Close()
	}
}

func (l *Logger) log(level LogLevel, msg string) {
	if level < l.level {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	// Get caller info
	_, file, line, ok := runtime.Caller(2)
	caller := "?"
	if ok {
		// Only keep filename, not full path
		parts := strings.Split(file, "/")
		caller = fmt.Sprintf("%s:%d", parts[len(parts)-1], line)
	}

	ts := time.Now().Format("2006-01-02 15:04:05.000")
	levelStr := levelNames[level]

	// Write to file (no colors)
	fileLine := fmt.Sprintf("[%s] [%s] [%s] %s\n", ts, levelStr, caller, msg)
	if l.file != nil {
		io.WriteString(l.file, fileLine)
	}

	// Write to console with colors (only WARN and above, or if debug mode)
	if l.console && level >= LogWARN {
		color := levelColors[level]
		fmt.Printf("%s[%s] [%s]%s %s\n", color, levelStr, caller, colorReset, msg)
	}

	if level == LogFATAL {
		os.Exit(1)
	}
}

func (l *Logger) Debug(format string, args ...interface{}) {
	if l == nil { return }
	l.log(LogDEBUG, fmt.Sprintf(format, args...))
}

func (l *Logger) Info(format string, args ...interface{}) {
	if l == nil { return }
	l.log(LogINFO, fmt.Sprintf(format, args...))
}

func (l *Logger) Warn(format string, args ...interface{}) {
	if l == nil { return }
	l.log(LogWARN, fmt.Sprintf(format, args...))
}

func (l *Logger) Error(format string, args ...interface{}) {
	if l == nil { return }
	l.log(LogERROR, fmt.Sprintf(format, args...))
}

func (l *Logger) Fatal(format string, args ...interface{}) {
	if l == nil { return }
	l.log(LogFATAL, fmt.Sprintf(format, args...))
}

// LogPath returns the current log file path
func (l *Logger) LogPath() string {
	if l == nil { return "" }
	return l.logPath
}
