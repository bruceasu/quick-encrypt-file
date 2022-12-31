package me.asu.quick;

public interface Command {
    String name();
    int execute(String... args) throws Exception;
    String description();
}
