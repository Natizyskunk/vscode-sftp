// tslint:disable-next-line
// modified from https://raw.githubusercontent.com/sindresorhus/p-queue/a202b25d3e2f8d0472f85d501f7f558a7fa89b56/index.js

import { EventEmitter } from 'events';

export interface TaskProgress {
  /** Unique task identifier */
  taskId: string;
  /** Number of bytes transferred so far */
  bytesTransferred: number;
  /** Total bytes to transfer (0 if unknown) */
  totalBytes: number;
}

// Port of lower_bound from http://en.cppreference.com/w/cpp/algorithm/lower_bound
// Used to compute insertion index to keep queue sorted after insertion
function lowerBound<T>(array: T[], value: T, comp: (a: T, b: T) => number) {
  let first = 0;
  let count = array.length;

  while (count > 0) {
    // tslint:disable-next-line no-bitwise
    const step = (count / 2) | 0;
    let it = first + step;

    if (comp(array[it], value) <= 0) {
      first = ++it;
      count -= step + 1;
    } else {
      count = step;
    }
  }

  return first;
}

export interface Task {
  /** Human-readable label for queue UI */
  label?: string;
  /** Unique ID assigned by Scheduler */
  taskId?: string;
  /** Current task status */
  taskStatus?: 'pending' | 'running' | 'done' | 'error';
  run(): unknown | Promise<unknown>;
}

type taskFunc = Task['run'];

interface Queue<T> {
  enqueue(r: T): void;
  dequeue(): T;
  size: number;
}

class PriorityQueue<T> implements Queue<T> {
  constructor(private _queue: { priority: number; item: T }[] = []) {}

  enqueue(item: T, opts?) {
    opts = Object.assign(
      {
        priority: 0,
      },
      opts
    );

    const element = { priority: opts.priority, item };
    if (this.size && this._queue[this.size - 1].priority >= opts.priority) {
      this._queue.push(element);
      return;
    }

    const index = lowerBound(this._queue, element, (a, b) => b.priority - a.priority);
    this._queue.splice(index, 0, element);
  }

  dequeue(): T {
    return this._queue.shift()!.item;
  }

  clear() {
    this._queue.length = 0;
  }

  get size(): number {
    return this._queue.length;
  }
}

const EVENT_TASK_START = 'task.start';
const EVENT_TASK_DONE = 'task.done';
const EVENT_TASK_PROGRESS = 'task.progress';
const EVENT_IDLE = 'idle';

let _taskIdCounter = 0;
function nextTaskId(): string {
  return `task_${++_taskIdCounter}_${Date.now()}`;
}

class Scheduler {
  private _queue: PriorityQueue<Task> = new PriorityQueue<Task>();
  private _pendingCount: number = 0;
  private _eventEmitter: EventEmitter = new EventEmitter();
  private _concurrency: number;
  private _isPaused: boolean;

  constructor(opts: { concurrency?: number; autoStart?: boolean } = {}) {
    opts = Object.assign(
      {
        concurrency: Infinity,
        autoStart: true,
      },
      opts
    );

    if (!(typeof opts.concurrency === 'number' && opts.concurrency >= 1)) {
      throw new TypeError(
        `Expected \`concurrency\` to be a number from 1 and up, got \`${
          opts.concurrency
        }\` (${typeof opts.concurrency})`
      );
    }

    this._concurrency = opts.concurrency;
    this._isPaused = opts.autoStart === false;
  }

  setConcurrency(concurrency: number) {
    this._concurrency = concurrency;
  }

  add(task: Task | taskFunc, opt?: { priority: number }) {
    if (typeof task === 'function') {
      task = {
        run: task,
      };
    }

    if (!this._isPaused && this._pendingCount < this._concurrency) {
      this._runTask(task);
    } else {
      this._queue.enqueue(task, opt);
    }
  }

  addAll(tasks: (Task | taskFunc)[]) {
    tasks.forEach(t => this.add(t));
  }

  start() {
    if (!this._isPaused) {
      return;
    }

    this._isPaused = false;
    while (this.size > 0 && this._pendingCount < this._concurrency) {
      this._runTask(this._queue.dequeue());
    }
  }

  pause() {
    this._isPaused = true;
  }

  empty() {
    this._queue.clear();
  }

  onTaskStart(listener: (task: Task) => void) {
    this._eventEmitter.on(EVENT_TASK_START, listener);
  }

  onTaskDone(listener: (err: Error | null, task: Task) => void) {
    this._eventEmitter.on(EVENT_TASK_DONE, listener);
  }

  onTaskProgress(listener: (progress: TaskProgress) => void) {
    this._eventEmitter.on(EVENT_TASK_PROGRESS, listener);
  }

  emitProgress(progress: TaskProgress) {
    this._eventEmitter.emit(EVENT_TASK_PROGRESS, progress);
  }

  onIdle(listener: () => void) {
    this._eventEmitter.on(EVENT_IDLE, listener);
  }

  /** Returns a snapshot of all pending tasks in the queue */
  getQueue(): Task[] {
    return (this._queue as any)._queue.map((item: { item: Task }) => item.item);
  }

  /** Schedule a task to run again (for retry after error) */
  retry(task: Task) {
    if (task.taskStatus === 'error') {
      task.taskStatus = 'pending';
      this.add(task);
    }
  }

  get isRunning() {
    return !this._isPaused;
  }

  get size() {
    return this._queue.size;
  }

  get pendingCount() {
    return this._pendingCount;
  }

  private _next() {
    if (this.size > 0) {
      if (!this._isPaused) {
        this._runTask(this._queue.dequeue());
      }
    } else if (this._pendingCount <= 0) {
      this._eventEmitter.emit(EVENT_IDLE);
    }
  }

  private async _runTask(task: Task) {
    this._pendingCount += 1;
    task.taskId = task.taskId || nextTaskId();
    task.taskStatus = 'running';
    this._eventEmitter.emit(EVENT_TASK_START, task);

    let error = null;
    try {
      await task.run();
      task.taskStatus = 'done';
    } catch (err) {
      error = err;
      task.taskStatus = 'error';
    } finally {
      this._pendingCount -= 1;
      this._eventEmitter.emit(EVENT_TASK_DONE, error, task);
      this._next();
    }
  }
}

export default Scheduler;
