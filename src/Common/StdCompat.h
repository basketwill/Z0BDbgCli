#pragma once

#include <windows.h>
#include <process.h>
#include <utility>

namespace std {

class mutex {
public:
    mutex() { InitializeCriticalSection(&cs_); }
    ~mutex() { DeleteCriticalSection(&cs_); }
    void lock() { EnterCriticalSection(&cs_); }
    void unlock() { LeaveCriticalSection(&cs_); }
    bool try_lock() { return TryEnterCriticalSection(&cs_) != 0; }
private:
    mutex(const mutex&);
    mutex& operator=(const mutex&);
    CRITICAL_SECTION cs_;
};

template <typename MutexType>
class lock_guard {
public:
    explicit lock_guard(MutexType& m) : m_(m) { m_.lock(); }
    ~lock_guard() { m_.unlock(); }
private:
    MutexType& m_;
    lock_guard(const lock_guard&);
    lock_guard& operator=(const lock_guard&);
};

template <typename MutexType>
class unique_lock {
public:
    unique_lock() : m_(0), owns_(false) {}
    explicit unique_lock(MutexType& m) : m_(&m), owns_(true) { m_->lock(); }
    unique_lock(MutexType& m, bool adopt) : m_(&m), owns_(adopt) {}
    ~unique_lock() { if (owns_ && m_) m_->unlock(); }
    void unlock() { if (owns_ && m_) { m_->unlock(); owns_ = false; } }
    MutexType* mutex() const { return m_; }
    bool owns_lock() const { return owns_; }
    operator bool() const { return owns_; }
private:
    MutexType* m_;
    bool owns_;
    unique_lock(const unique_lock&);
    unique_lock& operator=(const unique_lock&);
};

class condition_variable {
public:
    condition_variable() { event_ = CreateEventW(NULL, FALSE, FALSE, NULL); }
    ~condition_variable() { if (event_ != NULL) CloseHandle(event_); }
    void notify_one() { SetEvent(event_); }
    void notify_all() { PulseEvent(event_); }
    template <typename LockType, typename Predicate>
    void wait(LockType& lock, Predicate pred) {
        while (!pred()) {
            CRITICAL_SECTION* cs = reinterpret_cast<CRITICAL_SECTION*>(lock.mutex());
            LeaveCriticalSection(cs);
            WaitForSingleObject(event_, INFINITE);
            EnterCriticalSection(cs);
        }
    }
private:
    condition_variable(const condition_variable&);
    condition_variable& operator=(const condition_variable&);
    HANDLE event_;
};

struct nullopt_t { explicit nullopt_t(int) {} };
static const nullopt_t nullopt = nullopt_t(0);

template <typename T>
class optional {
public:
    optional() : hasValue_(false), value_() {}
    optional(nullopt_t) : hasValue_(false), value_() {}
    optional(const T& value) : hasValue_(true), value_(value) {}
    optional(const optional& other) : hasValue_(other.hasValue_), value_(other.value_) {}
    optional& operator=(nullopt_t) { hasValue_ = false; return *this; }
    optional& operator=(const T& value) { hasValue_ = true; value_ = value; return *this; }
    optional& operator=(const optional& other) { hasValue_ = other.hasValue_; value_ = other.value_; return *this; }
    const T& operator*() const { return value_; }
    T& operator*() { return value_; }
    const T* operator->() const { return &value_; }
    T* operator->() { return &value_; }
    operator bool() const { return hasValue_; }
    bool has_value() const { return hasValue_; }
    const T& value() const { return value_; }
    T& value() { return value_; }
private:
    bool hasValue_;
    T value_;
};

class thread {
public:
    thread() : handle_(NULL), id_(0) {}
    template <typename Func>
    explicit thread(Func f) {
        Func* fp = new Func(f);
        handle_ = reinterpret_cast<HANDLE>(_beginthreadex(NULL, 0, &thread_func<Func>, fp, 0, &id_));
        if (handle_ == NULL) delete fp;
    }
    template <typename Func, typename Arg>
    thread(Func f, Arg a) {
        std::pair<Func, Arg>* fp = new std::pair<Func, Arg>(f, a);
        handle_ = reinterpret_cast<HANDLE>(_beginthreadex(NULL, 0, &thread_func2<Func, Arg>, fp, 0, &id_));
        if (handle_ == NULL) delete fp;
    }
    ~thread() { if (handle_ != NULL) CloseHandle(handle_); }
    bool joinable() const { return handle_ != NULL; }
    void join() { if (handle_ != NULL) { WaitForSingleObject(handle_, INFINITE); CloseHandle(handle_); handle_ = NULL; } }
    void detach() { if (handle_ != NULL) { CloseHandle(handle_); handle_ = NULL; } }
    thread& operator=(const thread& rhs) {
        if (this != &rhs) {
            if (handle_ != NULL) { CloseHandle(handle_); }
            handle_ = rhs.handle_;
            id_ = rhs.id_;
            const_cast<thread&>(rhs).handle_ = NULL;
            const_cast<thread&>(rhs).id_ = 0;
        }
        return *this;
    }
private:
    template <typename Func>
    static unsigned __stdcall thread_func(void* arg) {
        Func* fp = static_cast<Func*>(arg);
        Func f = *fp;
        delete fp;
        f();
        return 0;
    }
    template <typename Func, typename Arg>
    static unsigned __stdcall thread_func2(void* arg) {
        std::pair<Func, Arg>* fp = static_cast<std::pair<Func, Arg>*>(arg);
        Func f = fp->first;
        Arg a = fp->second;
        delete fp;
        (*a.*f)();
        return 0;
    }
    HANDLE handle_;
    unsigned id_;
    thread(const thread&);
};

template <typename T>
const T& clamp(const T& value, const T& lo, const T& hi) {
    if (value < lo) return lo;
    if (hi < value) return hi;
    return value;
}

}  // namespace std