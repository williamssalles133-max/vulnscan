package com.williams.vulnscan.data;

public final class Event<T> {
    private final T content;
    private boolean handled;

    public Event(T content) {
        this.content = content;
    }

    public T getIfNotHandled() {
        if (handled) {
            return null;
        }
        handled = true;
        return content;
    }
}
