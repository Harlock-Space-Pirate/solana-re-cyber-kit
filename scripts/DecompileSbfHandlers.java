//Decompile named sBPF handlers at known addresses and dump C-like decompiler output.
//
//@category Solana
//@menupath
//
// Args:
//   [0] output directory
//   [1] handlers CSV path: name,elf_vaddr_hex,sol_addr_hex,disc8

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class DecompileSbfHandlers extends GhidraScript {

	private static class HandlerSpec {
		String name;
		long elfVaddr;
		long solAddr;
		String disc8;
	}

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 2) {
			printerr("Usage: DecompileSbfHandlers.java <outDir> <handlers.csv>");
			return;
		}
		File outDir = new File(args[0]);
		if (!outDir.exists() && !outDir.mkdirs()) {
			printerr("Cannot create outDir: " + outDir);
			return;
		}
		List<HandlerSpec> handlers = loadCsv(new File(args[1]));
		println("Loaded " + handlers.size() + " handlers");
		println("Program: " + currentProgram.getName());
		println("Language: " + currentProgram.getLanguageID());
		println("ImageBase: " + currentProgram.getImageBase());

		Memory mem = currentProgram.getMemory();
		for (MemoryBlock b : mem.getBlocks()) {
			println(String.format("  block %s [%s - %s] exec=%s init=%s",
				b.getName(), b.getStart(), b.getEnd(), b.isExecute(), b.isInitialized()));
		}

		DecompInterface ifc = new DecompInterface();
		ifc.setOptions(ifc.getOptions());
		if (!ifc.openProgram(currentProgram)) {
			printerr("Decompiler openProgram failed: " + ifc.getLastMessage());
			return;
		}

		FunctionManager fm = currentProgram.getFunctionManager();
		ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
		List<String> indexLines = new ArrayList<>();
		indexLines.add("# c4-sage Ghidra decomp (top live handlers)");
		indexLines.add("");
		indexLines.add("| name | disc8 | addr_used | status | file |");
		indexLines.add("|------|-------|-----------|--------|------|");

		int ok = 0;
		for (HandlerSpec h : handlers) {
			Address addr = resolveAddress(mem, h);
			String status;
			String outName = h.name + "_" + h.disc8 + ".c";
			File outFile = new File(outDir, outName);

			if (addr == null) {
				status = "NO_ADDR";
				writeStub(outFile, h, null, "Could not resolve address in memory map");
				indexLines.add(String.format("| %s | %s | - | %s | %s |", h.name, h.disc8, status, outName));
				printerr("NO_ADDR " + h.name + " elf=" + Long.toHexString(h.elfVaddr) + " sol=" + Long.toHexString(h.solAddr));
				continue;
			}

			Function fn = fm.getFunctionAt(addr);
			if (fn == null) {
				// clear prior wrong data; force disasm then function
				try {
					clearListing(addr);
				}
				catch (Exception e) {
					// ignore
				}
				disassemble(addr);
				fn = createFunction(addr, h.name);
			}
			if (fn == null) {
				// last resort: body = single insn then expand
				disassemble(addr);
				fn = createFunction(addr, h.name);
			}
			if (fn == null) {
				fn = getFunctionContaining(addr);
				if (fn != null && !fn.getEntryPoint().equals(addr)) {
					// wrong containing fn — try remove body conflict by renaming only
					fn = null;
				}
			}
			if (fn != null && !h.name.equals(fn.getName())) {
				try {
					fn.setName(h.name, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					// keep existing name
				}
			}
			if (fn == null) {
				status = "NO_FUNC";
				writeStub(outFile, h, addr, "createFunction failed at " + addr);
				indexLines.add(String.format("| %s | %s | %s | %s | %s |", h.name, h.disc8, addr, status, outName));
				printerr("NO_FUNC " + h.name + " @ " + addr);
				continue;
			}

			DecompileResults res = ifc.decompileFunction(fn, 120, monitor);
			String c = null;
			if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
				c = res.getDecompiledFunction().getC();
			}
			if (c == null || c.isEmpty()) {
				status = "DECOMP_FAIL";
				String msg = res == null ? "null results" : res.getErrorMessage();
				writeStub(outFile, h, addr, "decompile failed: " + msg);
				indexLines.add(String.format("| %s | %s | %s | %s | %s |", h.name, h.disc8, addr, status, outName));
				printerr("DECOMP_FAIL " + h.name + " @ " + addr + " : " + msg);
				continue;
			}

			try (PrintWriter pw = new PrintWriter(new FileWriter(outFile))) {
				pw.println("/*");
				pw.println(" * Ghidra decompiler output — c4-sage handler");
				pw.println(" * name: " + h.name);
				pw.println(" * disc8: " + h.disc8);
				pw.println(" * sol_addr: 0x" + Long.toHexString(h.solAddr));
				pw.println(" * elf_vaddr: 0x" + Long.toHexString(h.elfVaddr));
				pw.println(" * ghidra_addr: " + addr);
				pw.println(" * language: " + currentProgram.getLanguageID());
				pw.println(" * NOTE: raw decompiler C; pair with pseudo-Rust under readable-source/c4-sage/instructions/");
				pw.println(" */");
				pw.println();
				pw.print(c);
				if (!c.endsWith("\n")) {
					pw.println();
				}
			}
			status = "OK";
			ok++;
			indexLines.add(String.format("| %s | %s | %s | %s | %s |", h.name, h.disc8, addr, status, outName));
			println("OK " + h.name + " @ " + addr + " -> " + outFile.getName() + " (" + c.length() + " chars)");
		}

		ifc.dispose();

		indexLines.add("");
		indexLines.add("OK " + ok + "/" + handlers.size());
		File index = new File(outDir, "INDEX.md");
		try (PrintWriter pw = new PrintWriter(new FileWriter(index))) {
			for (String line : indexLines) {
				pw.println(line);
			}
		}
		println("Wrote INDEX.md — " + ok + "/" + handlers.size() + " decompiled");
	}

	private Address resolveAddress(Memory mem, HandlerSpec h) {
		// c4-sage.so: Ghidra maps vaddr==file offset. sol = 0x100000000 + text_off.
		// Correct ghidra = text_off = sol - 0x100000000. NEVER add ImageBase 0x120
		// (that lands mid-function). CSV elf_vaddr column should hold text_off.
		long textOff = h.solAddr >= 0x100000000L ? (h.solAddr - 0x100000000L) : h.elfVaddr;
		long[] candidates = new long[] {
			textOff,
			h.elfVaddr,
			h.solAddr,
		};
		for (long raw : candidates) {
			if (raw < 0) {
				continue;
			}
			try {
				Address a = toAddr(raw);
				if (mem.contains(a) && mem.getBlock(a) != null && mem.getBlock(a).isInitialized()) {
					// require at least one readable byte
					mem.getByte(a);
					return a;
				}
			}
			catch (Exception e) {
				// try next
			}
		}
		// Last resort: any candidate that is in an execute block even if getByte fails
		for (long raw : candidates) {
			try {
				Address a = toAddr(raw);
				MemoryBlock b = mem.getBlock(a);
				if (b != null && b.isExecute()) {
					return a;
				}
			}
			catch (Exception e) {
				// ignore
			}
		}
		return null;
	}

	private static List<HandlerSpec> loadCsv(File csv) throws Exception {
		List<HandlerSpec> out = new ArrayList<>();
		try (BufferedReader br = new BufferedReader(new FileReader(csv))) {
			String line;
			while ((line = br.readLine()) != null) {
				line = line.trim();
				if (line.isEmpty() || line.startsWith("#") || line.startsWith("name,")) {
					continue;
				}
				String[] p = line.split(",");
				if (p.length < 3) {
					continue;
				}
				HandlerSpec h = new HandlerSpec();
				h.name = p[0].trim();
				h.elfVaddr = Long.decode(p[1].trim());
				h.solAddr = Long.decode(p[2].trim());
				h.disc8 = p.length > 3 ? p[3].trim() : "00000000";
				out.add(h);
			}
		}
		return out;
	}

	private static void writeStub(File outFile, HandlerSpec h, Address addr, String reason) throws Exception {
		try (PrintWriter pw = new PrintWriter(new FileWriter(outFile))) {
			pw.println("/* DECOMP FAILED");
			pw.println(" * name: " + h.name);
			pw.println(" * disc8: " + h.disc8);
			pw.println(" * sol_addr: 0x" + Long.toHexString(h.solAddr));
			pw.println(" * elf_vaddr: 0x" + Long.toHexString(h.elfVaddr));
			pw.println(" * ghidra_addr: " + (addr == null ? "null" : addr.toString()));
			pw.println(" * reason: " + reason);
			pw.println(" */");
		}
	}
}
