//Recursively decompile a root sBPF function and all callees up to a max depth.
//Resolves callee addresses via Ghidra's own reference model (correct pcrel), so
//no manual sBPF call-offset arithmetic. Dumps one .c per function + a tree index.
//
//@category Solana
//@menupath
//
// Args:
//   [0] output directory
//   [1] root sol_addr hex (e.g. 0x1002d7f40) OR text_off hex (e.g. 0x2d7f40)
//   [2] max depth (int, e.g. 3)

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class DecompileCallTree extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 3) {
			printerr("Usage: DecompileCallTree.java <outDir> <rootAddrHex> <maxDepth>");
			return;
		}
		File outDir = new File(args[0]);
		outDir.mkdirs();
		long rawAddr = Long.decode(args[1]);
		long textOff = rawAddr >= 0x100000000L ? rawAddr - 0x100000000L : rawAddr;
		int maxDepth = Integer.parseInt(args[2]);

		Memory mem = currentProgram.getMemory();
		FunctionManager fm = currentProgram.getFunctionManager();
		ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
		DecompInterface ifc = new DecompInterface();
		ifc.setOptions(ifc.getOptions());
		if (!ifc.openProgram(currentProgram)) {
			printerr("openProgram failed: " + ifc.getLastMessage());
			return;
		}

		Address root = toAddr(textOff);
		Function rootFn = ensureFunction(fm, root);
		if (rootFn == null) {
			printerr("Cannot resolve root function at " + root);
			return;
		}

		Set<Long> seen = new HashSet<>();
		List<String> index = new ArrayList<>();
		index.add("# Call-tree decompile from " + rootFn.getName() + " @ " + root + " (depth " + maxDepth + ")");
		index.add("");

		// BFS over callees using Ghidra's reference model (correct call resolution).
		ArrayDeque<Object[]> q = new ArrayDeque<>();
		q.add(new Object[] { rootFn, 0 });
		int ok = 0;
		while (!q.isEmpty()) {
			Object[] item = q.poll();
			Function fn = (Function) item[0];
			int depth = (Integer) item[1];
			long key = fn.getEntryPoint().getOffset();
			if (seen.contains(key)) {
				continue;
			}
			seen.add(key);

			String base = fn.getName() + "_" + Long.toHexString(key);
			File outFile = new File(outDir, base + ".c");
			DecompileResults res = ifc.decompileFunction(fn, 120, monitor);
			String c = null;
			if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
				c = res.getDecompiledFunction().getC();
			}
			String indent = "  ".repeat(depth);
			if (c == null || c.isEmpty()) {
				index.add(indent + "- " + base + " : DECOMP_FAIL");
			}
			else {
				try (PrintWriter pw = new PrintWriter(new FileWriter(outFile))) {
					pw.println("/* Ghidra call-tree decompile");
					pw.println(" * fn: " + fn.getName());
					pw.println(" * entry: " + fn.getEntryPoint() + "  (sol 0x" + Long.toHexString(0x100000000L + key) + ")");
					pw.println(" * depth: " + depth);
					pw.println(" */");
					pw.println();
					pw.print(c);
				}
				index.add(indent + "- " + base + " -> " + outFile.getName());
				ok++;
			}

			if (depth < maxDepth) {
				Set<Function> callees = fn.getCalledFunctions(monitor);
				for (Function callee : callees) {
					if (callee == null || callee.isExternal()) {
						continue;
					}
					if (!isExecutable(callee)) {
						index.add(indent + "- " + callee.getName() + " : SKIP_DATA");
						continue;
					}
					if (!seen.contains(callee.getEntryPoint().getOffset())) {
						q.add(new Object[] { callee, depth + 1 });
					}
				}
			}
		}
		ifc.dispose();

		index.add("");
		index.add("Decompiled " + ok + " functions.");
		File idx = new File(outDir, "CALLTREE-INDEX.md");
		try (PrintWriter pw = new PrintWriter(new FileWriter(idx))) {
			for (String l : index) {
				pw.println(l);
			}
		}
		println("Call-tree done: " + ok + " functions -> " + outDir);
	}

	/** Skip Ghidra "functions" whose entry is in rodata/data — those dumps are string soup. */
	private boolean isExecutable(Function fn) {
		MemoryBlock b = currentProgram.getMemory().getBlock(fn.getEntryPoint());
		if (b == null) {
			return true;
		}
		if (!b.isExecute()) {
			return false;
		}
		String n = b.getName().toLowerCase();
		return !(n.contains("data") || n.contains("rodata") || n.contains("const"));
	}

	private Function ensureFunction(FunctionManager fm, Address addr) {
		Function fn = fm.getFunctionAt(addr);
		if (fn != null) {
			return fn;
		}
		try {
			clearListing(addr);
		}
		catch (Exception e) {
			// ignore
		}
		disassemble(addr);
		fn = createFunction(addr, null);
		if (fn == null) {
			fn = getFunctionContaining(addr);
		}
		return fn;
	}
}
