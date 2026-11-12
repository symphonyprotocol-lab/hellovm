import threading, queue, time
results = []
lock = threading.Lock()
def work(n):
    total = sum(i * i for i in range(n))
    with lock:
        results.append(total)
threads = [threading.Thread(target=work, args=(20000 + i,)) for i in range(8)]
for t in threads: t.start()
for t in threads: t.join()
print("threads:", len(results), sorted(results) == sorted(sum(i * i for i in range(20000 + i)) for i in range(8)))
q = queue.Queue()
def producer():
    for i in range(100): q.put(i)
    q.put(None)
t = threading.Thread(target=producer); t.start()
got = []
while (item := q.get()) is not None: got.append(item)
t.join()
print("queue:", sum(got))
ev = threading.Event()
threading.Timer(0.05, ev.set).start()
print("event:", ev.wait(5))
