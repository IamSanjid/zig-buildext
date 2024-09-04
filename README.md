# zig-buildext
Some useful functions/packages available at `build.zig` phase.
Just add a dependency to your `build.zig.zon` file.
In `build.zig`:
```zig
const std = @import("std");
const ext = @import("zig-buildext");
const fluent = ext.fluent; // No need to depend on Fluent(https://github.com/andrewCodeDev/Fluent);

fn build(b: *std.Build) void {
    // use ext functions
    // use fluent
}
```