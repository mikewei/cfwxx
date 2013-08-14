#pragma once

#include <time.h>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <utility>
#include <glog/logging.h>
#include "cfw.h"

CFW_NS_BEGIN

template <class T>
class Channel
{
public:
	typedef uint64_t Key;
	struct Queue {
		Queue() {
			Touch();
		}
		void Touch() {
			last_active = ::time(nullptr);
		}
		std::queue<std::shared_ptr<T>> queue;
		std::mutex mutex;
		std::mutex own;
		time_t last_active;
	};
	std::shared_ptr<T> Pop(Key k);
	void Push(Key k, const std::shared_ptr<T>& v);
	void Push(Key k, std::shared_ptr<T>&& v);
	bool Own(Key k);
	void Free(Key k);
	void GarbageCleanup(time_t secs);
private:
	std::shared_ptr<Queue> GetQueue(Key k, bool create);
private:
	std::map<Key, std::shared_ptr<Queue>> map_;
	std::mutex map_mutex_;
};

template <class Q>
struct PopHelper
{
	PopHelper(Q& q) : q_(q) {}
	~PopHelper() {
		q_.pop();
	}
	Q& q_;
};

template <class T>
std::shared_ptr<typename Channel<T>::Queue> Channel<T>::GetQueue(Key k, bool create)
{
	std::lock_guard<std::mutex> lock(map_mutex_);
	auto it = map_.find(k);
	if (it == map_.end()) {
		if (create) {
			return (map_[k] = std::make_shared<Queue>());
		} else {
			return {};
		}
	} else {
		it->second->Touch();
		return it->second;
	}
}

template <class T>
void Channel<T>::GarbageCleanup(time_t secs)
{
	std::lock_guard<std::mutex> lock(map_mutex_);
	time_t now = ::time(nullptr);
	for (auto it : map_) {
		if (it.second->last_active + secs < now) {
			LOG(INFO) << "garbage cleanup key:" << it.first;
			map_.erase(it.first);
		}
	}
}

template <class T>
std::shared_ptr<T> Channel<T>::Pop(Key k)
{
	auto q = GetQueue(k, false);
	if (!q)
		return {};
	std::lock_guard<std::mutex> lock(q->mutex);
	if (q->queue.empty()) {
		return {};
	} else {
		PopHelper<decltype(q->queue)> pop(q->queue);
		return std::move(q->queue.front());
	}
}

template <class T>
void Channel<T>::Push(Key k, const std::shared_ptr<T>& v)
{
	auto q = GetQueue(k, true);
	std::lock_guard<std::mutex> lock(q->mutex);
	q->queue.push(v);
}

template <class T>
void Channel<T>::Push(Key k, std::shared_ptr<T>&& v)
{
	auto q = GetQueue(k, true);
	std::lock_guard<std::mutex> lock(q->mutex);
	q->queue.push(std::move(v));
}

template <class T>
bool Channel<T>::Own(Key k)
{
	auto q = GetQueue(k, true);
	return q->own.try_lock();
}

template <class T>
void Channel<T>::Free(Key k)
{
	std::lock_guard<std::mutex> lock(map_mutex_);
	map_.erase(k);
}

CFW_NS_END
