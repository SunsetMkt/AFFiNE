import { describe, expect, test, vi } from 'vitest';

import { Slot } from '../slot/slot.js';

describe('slot', () => {
  test('init', () => {
    const slot = new Slot();
    expect(slot).is.toBeDefined();
  });

  test('emit', () => {
    const slot = new Slot<void>();
    const callback = vi.fn();
    slot.on(callback);
    slot.emit();
    expect(callback).toBeCalled();
  });

  test('emit with value', () => {
    const slot = new Slot<number>();
    const callback = vi.fn(v => expect(v).toBe(5));
    slot.on(callback);
    slot.emit(5);
    expect(callback).toBeCalled();
  });

  test('listen once', () => {
    const slot = new Slot<number>();
    const callback = vi.fn(v => expect(v).toBe(5));
    slot.once(callback);
    slot.emit(5);
    slot.emit(6);
    expect(callback).toBeCalledTimes(1);
  });

  test('listen once with dispose', () => {
    const slot = new Slot<void>();
    const callback = vi.fn(() => {
      throw new Error('');
    });
    const disposable = slot.once(callback);
    disposable.dispose();
    slot.emit();
    expect(callback).toBeCalledTimes(0);
  });

  test('cycle emit', () => {
    const slot = new Slot<number>();
    const callback = vi.fn(v => slot.emit(v + 1));
    slot.on(callback);
    slot.emit(0);
    expect(callback).toBeCalledTimes(1);
    expect(callback).toBeCalledWith(0);
  });
});
