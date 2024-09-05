const std = @import("std");
const builtin = @import("builtin");

pub const fluent = @import("fluent");

pub fn build(_: *std.Build) void {}

pub inline fn comptimeScalarReplace(
    comptime str: anytype,
    comptime fromScalar: u8,
    comptime toScalar: u8,
) *const [str.len:0]u8 {
    comptime {
        var buf: [str.len:0]u8 = undefined;
        for (str, 0..) |c, j| {
            if (c == fromScalar) {
                buf[j] = toScalar;
            } else {
                buf[j] = c;
            }
        }
        buf[buf.len] = 0;
        const final = buf;
        return &final;
    }
}

const desc_field_fmt = "__desc_{s}_desc__";
fn DescriptionFieldName(comptime name: []const u8) *const [std.fmt.count(desc_field_fmt, .{name}):0]u8 {
    return std.fmt.comptimePrint(desc_field_fmt, .{name});
}

fn isDescriptionFieldName(comptime name: []const u8) bool {
    if (comptime std.mem.startsWith(u8, name, "__desc") and
        std.mem.endsWith(u8, name, "_desc__"))
    {
        return true;
    }
    return false;
}

pub fn AsOptionalType(comptime T: type) type {
    return @Type(.{ .optional = .{ .child = T } });
}

fn StructFieldDefaultValue(comptime sf: std.builtin.Type.StructField) *const sf.type {
    const fi_type_dvalue = sf.default_value.?;
    const fi_type_aligned: *align(sf.alignment) const anyopaque = @alignCast(fi_type_dvalue);
    return @as(*const sf.type, @ptrCast(fi_type_aligned));
}

pub fn BuildOptionsType(comptime T: type) type {
    const type_info = @typeInfo(T);
    const StructField = std.builtin.Type.StructField;
    if (type_info != .@"struct") {
        @compileError("expected tuple or struct argument, found " ++ @typeName(T));
    }
    const fields_info = type_info.@"struct".fields;
    comptime var new_fields: [fields_info.len * 2]StructField = undefined;

    inline for (fields_info, 0..) |fi, idx| {
        const i = idx * 2;
        const fi_type_info = @typeInfo(fi.type);
        if (fi_type_info != .@"struct") {
            @compileError("expected field(" ++ fi.name ++ ") type to be a tuple or struct argument, found " ++ @typeName(T));
        }

        const fi_args = fi_type_info.@"struct".fields;
        if ((fi_args.len != 2 and fi_args.len != 3) or !fi_type_info.@"struct".is_tuple) {
            @compileError("provide argument as `.{ .option_name = .{ type, \"Description\" } }` or `.{ .option_name = .{ type, \"Description\", default_value } }`");
        }

        const fi_type = StructFieldDefaultValue(fi_args[0]).*;

        if (fi_args.len == 3) {
            const as_default_value: ?*const anyopaque = if (fi_args[2].default_value != null)
                @ptrCast(&@as(fi_type, StructFieldDefaultValue(fi_args[2]).*))
            else
                null;
            new_fields[i] = StructField{
                .name = fi.name,
                .type = fi_type,
                .default_value = as_default_value,
                .is_comptime = false,
                .alignment = @alignOf(fi_type),
            };
        } else {
            const NullType = if (@typeInfo(fi_type) == .optional)
                fi_type
            else
                AsOptionalType(fi_type);
            const null_value: NullType = null;
            new_fields[i] = StructField{
                .name = fi.name,
                .type = NullType,
                .default_value = @ptrCast(&null_value),
                .is_comptime = false,
                .alignment = @alignOf(NullType),
            };
        }
        // description
        new_fields[i + 1] = StructField{
            .name = DescriptionFieldName(fi.name),
            .type = fi_args[1].type,
            .default_value = fi_args[1].default_value,
            .is_comptime = fi_args[1].is_comptime,
            .alignment = @alignOf(fi_args[1].type),
        };
    }

    return @Type(.{
        .@"struct" = .{
            .layout = .auto,
            .fields = new_fields[0..],
            .decls = &.{},
            .is_tuple = false,
            .backing_integer = null,
        },
    });
}

pub fn BuildOptions(comptime args: anytype) type {
    const ArgsType = if (@TypeOf(args) == type) args else @TypeOf(args);
    const OptionsType = BuildOptionsType(ArgsType);
    return struct {
        pub const Type = OptionsType;
        pub const RawType = ArgsType;
        pub const DepArgsType = ToDepArgsType();

        pub fn default() Type {
            return CreateDefaultStruct(Type);
        }

        pub fn parse(b: *std.Build, fmt_prefix: []const u8, overrides: anytype) Type {
            return parseBuildOptions(b, Type, fmt_prefix, overrides);
        }

        // Replaces '_' with '-' of the field names for proper "option name".
        // So that `std.Build.dependency` can parse those as options.
        pub fn toDependencyArgs(options: Type) DepArgsType {
            var dep_options: DepArgsType = undefined;
            inline for (@typeInfo(DepArgsType).@"struct".fields) |field| {
                const field_name = comptimeScalarReplace(field.name, '-', '_');
                @field(dep_options, field.name) = @field(options, field_name);
            }
            return dep_options;
        }

        fn ToDepArgsType() type {
            const type_info = @typeInfo(Type);
            const struct_info = type_info.@"struct";

            // Don't need the "description fields"
            comptime var fields: [struct_info.fields.len / 2]std.builtin.Type.StructField = undefined;
            comptime var field_idx = 0;

            inline for (type_info.@"struct".fields) |field| {
                if (!isDescriptionFieldName(field.name)) {
                    fields[field_idx] = field;
                    fields[field_idx].name = comptimeScalarReplace(field.name, '_', '-');
                    field_idx += 1;
                }
            }

            return @Type(.{
                .@"struct" = .{
                    .layout = .auto,
                    .fields = fields[0..],
                    .decls = &.{},
                    .is_tuple = false,
                    .backing_integer = null,
                },
            });
        }
    };
}

pub fn CreateDefaultStruct(comptime T: type) T {
    const type_info = @typeInfo(T);
    if (type_info != .@"struct") {
        @compileError("expected tuple or struct argument, found " ++ @typeName(T));
    }
    const fields_info = type_info.@"struct".fields;
    var instance: T = undefined;

    inline for (fields_info) |fi| {
        if (fi.default_value) |dvalue| {
            const dvalue_aligned: *align(fi.alignment) const anyopaque = @alignCast(dvalue);
            const value = @as(*const fi.type, @ptrCast(dvalue_aligned)).*;
            @field(instance, fi.name) = value;
            //_ = dvalue;
            //@field(instance, fi.name) = StructFieldDefaultValue(fi).*;
        }
    }

    return instance;
}

pub fn parseImmidiateBuildOptions(
    b: *std.Build,
    imm_options: anytype,
    fmt_prefix: []const u8,
) BuildOptionsType(@TypeOf(imm_options)) {
    const OptionsType = BuildOptions(@TypeOf(imm_options));
    var instance: OptionsType.Type = undefined;

    const imm_opt_field_infos = @typeInfo(OptionsType.RawType).@"struct".fields;
    inline for (imm_opt_field_infos) |imm_fi| {
        const has_default = @typeInfo(imm_fi.type).@"struct".fields.len == 3;
        const fi_type = @TypeOf(@field(instance, imm_fi.name));
        const fi_type_info = @typeInfo(fi_type);

        const is_optional = fi_type_info == .optional;
        const imm_option_type = if (is_optional)
            fi_type_info.optional.child
        else
            fi_type;

        // Could be a runtime option.
        @field(instance, DescriptionFieldName(imm_fi.name)) = @field(imm_options, imm_fi.name)[1];
        switch (imm_option_type) {
            std.Build.ResolvedTarget => {
                if (has_default) {
                    @field(instance, imm_fi.name) = @field(imm_options, imm_fi.name)[2];
                } else if (is_optional) {
                    @field(instance, imm_fi.name) = b.standardTargetOptions(.{});
                }
            },
            std.builtin.OptimizeMode => {
                if (has_default) {
                    @field(instance, imm_fi.name) = @field(imm_options, imm_fi.name)[2];
                } else if (is_optional) {
                    @field(instance, imm_fi.name) = b.standardOptimizeOption(.{});
                }
            },
            else => {
                if (b.option(
                    imm_option_type,
                    b.fmt("{s}{s}", .{ fmt_prefix, comptimeScalarReplace(imm_fi.name, '_', '-') }),
                    @field(imm_options, imm_fi.name)[1],
                )) |value| {
                    @field(instance, imm_fi.name) = value;
                } else if (has_default) {
                    @field(instance, imm_fi.name) = @field(imm_options, imm_fi.name)[2];
                }
            },
        }
    }

    return instance;
}

pub fn parseBuildOptions(
    b: *std.Build,
    comptime T: type,
    fmt_prefix: []const u8,
    overrides: anytype,
) T {
    const OverridesType = @TypeOf(overrides);
    const overrides_type_info = @typeInfo(OverridesType);
    if (overrides_type_info != .@"struct") {
        @compileError("for overrides expected tuple or struct argument, found " ++ @typeName(OverridesType));
    }
    const args_type_info = @typeInfo(T);
    var instance = CreateDefaultStruct(T);

    const fields_info = args_type_info.@"struct".fields;
    inline for (fields_info) |fi| {
        const final_fi_type_info = @typeInfo(fi.type);

        if (comptime isDescriptionFieldName(fi.name)) continue;

        const is_optional = final_fi_type_info == .optional;
        const fi_type = if (is_optional)
            final_fi_type_info.optional.child
        else
            fi.type;

        const option_name = comptimeScalarReplace(fi.name, '_', '-');
        if (@hasField(OverridesType, fi.name)) {
            @field(instance, fi.name) = @field(overrides, fi.name);
        } else if (@hasField(OverridesType, option_name)) {
            @field(instance, fi.name) = @field(overrides, option_name);
        } else {
            switch (fi_type) {
                std.Build.ResolvedTarget => {
                    if (is_optional) {
                        @field(instance, fi.name) = b.standardTargetOptions(.{});
                    }
                },
                std.builtin.OptimizeMode => {
                    if (is_optional) {
                        @field(instance, fi.name) = b.standardOptimizeOption(.{});
                    }
                },
                else => {
                    if (@hasField(T, DescriptionFieldName(fi.name))) {
                        if (b.option(
                            fi_type,
                            b.fmt("{s}{s}", .{ fmt_prefix, option_name }),
                            @field(instance, DescriptionFieldName(fi.name)),
                        )) |value| {
                            @field(instance, fi.name) = value;
                        }
                    } else {
                        if (b.option(
                            fi_type,
                            b.fmt("{s}{s}", .{ fmt_prefix, option_name }),
                            "",
                        )) |value| {
                            @field(instance, fi.name) = value;
                        }
                    }
                },
            }
        }
    }

    return instance;
}

pub fn getOs(target: std.Target) []const u8 {
    return @tagName(target.os.tag);
}

pub fn getArch(target: std.Target) []const u8 {
    return @tagName(target.cpu.arch);
}

pub fn getAbi(target: std.Target) []const u8 {
    return @tagName(target.abi);
}

pub fn getPlatformStr(allocator: std.mem.Allocator, target: std.Target) ![]const u8 {
    return std.fmt.allocPrint(allocator, "{s}-{s}-{s}", .{
        getArch(target),
        getOs(target),
        getAbi(target),
    });
}

pub fn hasFileIn(dir_path: []const u8, file: []const u8) bool {
    var dir = std.fs.openDirAbsolute(dir_path, .{}) catch return false;
    defer dir.close();
    dir.access(file, .{}) catch return false;
    return true;
}

pub fn getNativePaths(
    arena: std.mem.Allocator,
    target: std.Target,
) !std.zig.system.NativePaths {
    var native_paths = try std.zig.system.NativePaths.detect(arena, target);

    if (builtin.target.os.tag == .windows and target.abi == .msvc) {
        const libc_installation = std.zig.LibCInstallation.findNative(.{
            .allocator = arena,
            .verbose = true,
            .target = target,
        }) catch return native_paths;

        if (libc_installation.include_dir) |include_dir| {
            try native_paths.addIncludeDir(include_dir);
        }

        if (libc_installation.sys_include_dir) |sys_include_dir| {
            try native_paths.addIncludeDir(sys_include_dir);
        }

        const MSVCToolsLibDirsSearcher = struct {
            allocator: std.mem.Allocator,
            nps: *std.zig.system.NativePaths,
            target_arch: ?std.Target.Cpu.Arch = null,
            lib_dir_names: ?std.ArrayList([]const u8) = null,
            arch_dir: ?[]const u8 = null,

            const tools_part = "Tools" ++ std.fs.path.sep_str;
            const tools_msvc_part = tools_part ++ "MSVC";
            const possible_lib_dir_names: []const []const u8 = &.{
                "Lib",
                "Libs",
                "lib",
                "libs",
                "bin",
            };
            const non_x86_arch_dir_names: []const []const u8 = &.{
                "arm",
                "arm64",
                "x64",
            };

            fn searchAndAddLibDirs(self: *@This(), dir: std.fs.Dir) !void {
                const dir_path = try dir.realpathAlloc(self.allocator, "");
                if (std.mem.indexOf(u8, dir_path, tools_msvc_part) != null) return;

                const arch_dir = self.arch_dir.?;

                const is_x86 = self.target_arch.? == .x86;
                var files = dir.iterate();
                while (try files.next()) |file| {
                    if (file.kind != .directory) {
                        continue;
                    }

                    var found_lib_dir = false;
                    for (self.lib_dir_names.?.items) |lib_dir_name| {
                        if (std.ascii.eqlIgnoreCase(file.name, lib_dir_name)) {
                            found_lib_dir = true;
                            if (is_x86 and std.ascii.indexOfIgnoreCase(dir_path, "x86") == null) {
                                for (non_x86_arch_dir_names) |other_arch_dir_name| {
                                    if (std.ascii.indexOfIgnoreCase(dir_path, other_arch_dir_name) != null) {
                                        found_lib_dir = false;
                                        break;
                                    }
                                }
                            }
                            break;
                        }
                    }

                    if (found_lib_dir) {
                        if (std.ascii.indexOfIgnoreCase(dir_path, arch_dir) == null and !is_x86) {
                            try self.nps.addLibDir(try std.fs.path.join(self.allocator, &.{ dir_path, file.name, arch_dir }));
                            try self.nps.addLibDir(try std.fs.path.join(self.allocator, &.{ dir_path, arch_dir, file.name }));
                        } else {
                            try self.nps.addLibDir(try std.fs.path.join(self.allocator, &.{ dir_path, file.name }));
                        }
                    } else {
                        var new_dir = try dir.openDir(file.name, .{
                            .iterate = true,
                            .no_follow = false,
                        });
                        defer new_dir.close();
                        try self.searchAndAddLibDirs(new_dir);
                    }
                }
            }
            // over engineered ikr but was having fun...
            fn setTargetArch(self: *@This(), target_arch: std.Target.Cpu.Arch) !void {
                self.target_arch = target_arch;
                self.arch_dir = switch (self.target_arch.?) {
                    .thumb => "arm",
                    .aarch64 => "arm64",
                    .x86 => "x86",
                    .x86_64 => "x64",
                    else => unreachable,
                };
                var lib_dir_names = std.ArrayList([]const u8).init(self.allocator);

                for (possible_lib_dir_names) |dir_name| {
                    try lib_dir_names.append(try self.allocator.dupe(u8, dir_name));
                    // didn't know about positional argument formatting.
                    // it wasn't a waste!
                    // https://zig.guide/standard-library/advanced-formatting
                    const formats = .{
                        "{0s}{1s}", // libx64
                        "{1s}.{0s}", // x64.lib
                        "{1s}-{0s}", // x64-lib
                        "{0s}-{1s}", // lib-x64
                        "{0s}.{1s}", // lib.x64
                        "{0s}_{1s}", // lib_x64
                    };
                    inline for (formats) |format| {
                        try lib_dir_names.append(try std.fmt.allocPrint(self.allocator, format, .{ dir_name, self.arch_dir.? }));
                    }
                }

                self.lib_dir_names = lib_dir_names;
            }

            // C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.40.33807\Lib\x64
            fn perform(self: *@This(), msvc_lib_dir: []const u8) !void {
                if (std.mem.indexOf(u8, msvc_lib_dir, tools_msvc_part)) |pos| {
                    const tools_dir = msvc_lib_dir[0..(pos + tools_part.len)];

                    var dir = try std.fs.openDirAbsolute(tools_dir, .{
                        .iterate = true,
                        .no_follow = false,
                    });
                    defer dir.close();
                    try self.searchAndAddLibDirs(dir);
                }
            }
        };
        var addMSVCToolsLibDirs = MSVCToolsLibDirsSearcher{
            .nps = &native_paths,
            .allocator = arena,
        };
        try addMSVCToolsLibDirs.setTargetArch(target.cpu.arch);

        if (libc_installation.msvc_lib_dir) |msvc_lib_dir| {
            try native_paths.addLibDir(msvc_lib_dir);
            // add every lib path TOOLS
            addMSVCToolsLibDirs.perform(msvc_lib_dir) catch {};
        }

        if (libc_installation.kernel32_lib_dir) |kernel32_lib_dir| {
            try native_paths.addLibDir(kernel32_lib_dir);
        }
    }

    return native_paths;
}

// searches framework and libs dir...
pub fn getObjSystemPath(
    native_paths: std.zig.system.NativePaths,
    obj_full_file: []const u8,
) ![]const u8 {
    for (native_paths.lib_dirs.items) |lib_dir| {
        const resolved_lib_dir = try std.fs.path.resolve(native_paths.arena, &.{lib_dir});
        if (hasFileIn(resolved_lib_dir, obj_full_file)) {
            return try std.fs.path.join(native_paths.arena, &.{ resolved_lib_dir, obj_full_file });
        }
    }
    for (native_paths.framework_dirs.items) |framework_dir| {
        const resolved_lib_dir = try std.fs.path.resolve(native_paths.arena, &.{framework_dir});
        if (hasFileIn(resolved_lib_dir, obj_full_file)) {
            return try std.fs.path.join(native_paths.arena, &.{ resolved_lib_dir, obj_full_file });
        }
    }
    for (native_paths.rpaths.items) |rpath| {
        const resolved_lib_dir = try std.fs.path.resolve(native_paths.arena, &.{rpath});
        if (hasFileIn(resolved_lib_dir, obj_full_file)) {
            return try std.fs.path.join(native_paths.arena, &.{ resolved_lib_dir, obj_full_file });
        }
    }
    return error.FileNotFound;
}

pub fn linkLibsOf(
    module: *std.Build.Module,
    libs_path: std.Build.LazyPath,
    libs: []const []const u8,
    linkage_static: bool,
    read_symlink: bool,
) !void {
    const b = module.owner;
    var dir = libs_path.getPath3(b, null).openDir("", .{
        .iterate = true,
        .no_follow = true,
    }) catch |err| {
        std.log.warn("Can't link libs of \"{s}\": {}", .{ libs_path.getPath(b), err });
        return;
    };
    defer dir.close();
    const target = module.resolved_target.?.result;
    module.addLibraryPath(libs_path);

    const is_windows = target.os.tag == .windows;
    const possible_lib_prefix = "lib";
    const lib_prefix = if (target.isMinGW() and linkage_static) "lib" else target.libPrefix();
    const lib_suffixes: []const []const u8 = if (linkage_static)
        &.{ ".lib", ".a", ".dll.a" }
    else
        &.{ ".lib", ".so", ".dylib", ".dll.a" };

    var libs_set = std.StringHashMap(void).init(b.allocator);
    defer libs_set.deinit();
    for (libs) |lib| {
        libs_set.put(lib, {}) catch @panic("OOM");
    }

    var lib_files = dir.iterate();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    while (lib_files.next() catch |err| {
        std.log.warn("Can't link libs of \"{s}\": {}", .{ libs_path.getPath(b), err });
        return;
    }) |entry| {
        if (entry.kind == .sym_link and read_symlink) {
            const path = dir.realpath(entry.name, &buf) catch continue;
            var file = std.fs.openFileAbsolute(path, .{}) catch continue;
            file.close();
        } else if (entry.kind != .file) {
            continue;
        }

        var link_strat: enum { skip, auto, absolute } = .skip;
        var lib_name: []const u8 = entry.name;
        for (lib_suffixes) |suffix| {
            if (std.mem.endsWith(u8, lib_name, suffix)) {
                lib_name = lib_name[0..(lib_name.len - suffix.len)];
                link_strat = .auto;
                break;
            }
        }

        if (link_strat == .skip) {
            if (std.mem.indexOf(u8, lib_name, ".so.")) |pos| {
                if (pos > 0) {
                    lib_name = lib_name[0..pos];
                    link_strat = .absolute;
                }
            }
        }

        if (lib_prefix.len > 0 and link_strat == .auto) {
            if (std.mem.startsWith(u8, lib_name, lib_prefix)) {
                lib_name = lib_name[lib_prefix.len..];
            } else {
                link_strat = .absolute;
            }
        }
        check_set: {
            if (!libs_set.contains(entry.name) and !libs_set.contains(lib_name)) {
                if (link_strat != .skip and is_windows and lib_prefix.len == 0 and
                    std.mem.startsWith(u8, lib_name, possible_lib_prefix))
                {
                    if (libs_set.contains(lib_name[possible_lib_prefix.len..])) {
                        break :check_set;
                    }
                }
                continue;
            }
        }

        switch (link_strat) {
            .absolute => module.addObjectFile(libs_path.path(b, entry.name)),
            .auto => module.linkSystemLibrary(lib_name, .{}),
            .skip => {
                if (is_windows and std.mem.endsWith(u8, entry.name, ".dll")) {
                    const dll_path = libs_path.path(b, entry.name);
                    b.getInstallStep().dependOn(
                        &b.addInstallBinFile(dll_path, entry.name).step,
                    );
                }
            },
        }
    }
}

pub fn linkAllLibsOf(
    comp: *std.Build.Step.Compile,
    libs_path: std.Build.LazyPath,
    linkage_static: bool,
    read_symlink: bool,
    exclude_files: ?[]const []const u8,
) !void {
    const b = comp.step.owner;
    var dir = libs_path.getPath3(b, &comp.step).openDir("", .{
        .iterate = true,
        .no_follow = true,
    }) catch |err| {
        std.log.warn("Can't link libs of \"{s}\": {}", .{ libs_path.getPath(b), err });
        return;
    };
    defer dir.close();

    const target = comp.rootModuleTarget();
    const is_windows = target.os.tag == .windows;
    const lib_prefix = if (target.isMinGW() and linkage_static) "lib" else target.libPrefix();
    const lib_suffixes: []const []const u8 = if (linkage_static)
        &.{ ".lib", ".a", ".dll.a" }
    else
        &.{ ".lib", ".so", ".dylib", ".dll.a" };

    var lib_files = dir.iterate();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    outer_loop: while (lib_files.next() catch |err| {
        std.log.warn("Can't link libs of \"{s}\": {}", .{ libs_path.getPath(b), err });
        return;
    }) |entry| {
        if (entry.kind == .sym_link and read_symlink) {
            const path = dir.realpath(entry.name, &buf) catch continue;
            var file = std.fs.openFileAbsolute(path, .{}) catch continue;
            file.close();
        } else if (entry.kind != .file) {
            continue;
        }

        var link_strat: enum { skip, auto, absolute } = .skip;
        var lib_name: []const u8 = entry.name;
        for (lib_suffixes) |suffix| {
            if (std.mem.endsWith(u8, lib_name, suffix)) {
                lib_name = lib_name[0..(lib_name.len - suffix.len)];
                link_strat = .auto;
                break;
            }
        }

        if (link_strat == .skip) {
            if (std.mem.indexOf(u8, lib_name, ".so.")) |pos| {
                if (pos > 0) {
                    lib_name = lib_name[0..pos];
                    link_strat = .absolute;
                }
            }
        }

        if (lib_prefix.len > 0 and link_strat == .auto) {
            if (std.mem.startsWith(u8, lib_name, lib_prefix)) {
                lib_name = lib_name[lib_prefix.len..];
            } else {
                link_strat = .absolute;
            }
        }

        if (exclude_files) |efs| {
            for (efs) |exc_file| {
                if (std.mem.eql(u8, exc_file, entry.name) or
                    std.mem.eql(u8, exc_file, lib_name))
                {
                    continue :outer_loop;
                }
            }
        }

        switch (link_strat) {
            .absolute => comp.addObjectFile(libs_path.path(b, entry.name)),
            .auto => comp.linkSystemLibrary(lib_name),
            .skip => {
                if (is_windows and std.mem.endsWith(u8, entry.name, ".dll")) {
                    const dll_path = libs_path.path(b, entry.name);
                    b.getInstallStep().dependOn(
                        &b.addInstallBinFile(dll_path, entry.name).step,
                    );
                }
            },
        }
    }
}

// override_first, true, will always copy/install the last dll path found..
pub fn installDlls(
    b: *std.Build,
    dlls: []const []const u8,
    paths: []const []const u8,
    override_first: bool,
) !void {
    var dlls_set = std.StringHashMap(void).init(b.allocator);
    var dll_paths = std.StringHashMap(std.Build.LazyPath).init(b.allocator);
    for (dlls) |dll| {
        dlls_set.put(dll, {}) catch @panic("OOM");
    }
    const step = b.getInstallStep();
    const dll_suffix = ".dll";

    for (paths) |path_str| {
        const path = std.Build.LazyPath{ .cwd_relative = path_str };
        var dir = path.getPath3(b, step).openDir("", .{
            .iterate = true,
            .no_follow = true,
        }) catch |err| {
            switch (err) {
                error.FileNotFound, error.AccessDenied, error.NotDir => {
                    continue;
                },
                else => {
                    std.log.warn("Couldn't open the dir for file iteration: {}", .{err});
                    return;
                },
            }
        };
        defer dir.close();
        var files = dir.iterate();
        while (files.next() catch |err| {
            std.log.warn("Couldn't open a file: {}", .{err});
            continue;
        }) |entry| {
            if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, dll_suffix)) {
                continue;
            }
            if (!dlls_set.contains(entry.name) and
                !dlls_set.contains(entry.name[0 .. entry.name.len - dll_suffix.len]))
            {
                continue;
            }
            const contains: bool = dll_paths.contains(entry.name);
            if (!contains or (contains and override_first)) {
                const dll_path = path.path(b, entry.name);
                // the `dupe`? arena allocator ow yeah..
                dll_paths.put(b.dupe(entry.name), dll_path) catch @panic("OOM");
            }
        }
    }

    var dll_paths_iter = dll_paths.iterator();
    while (dll_paths_iter.next()) |dll_path| {
        b.getInstallStep().dependOn(
            &b.addInstallBinFile(dll_path.value_ptr.*, dll_path.key_ptr.*).step,
        );
    }
}
