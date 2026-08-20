// List all direct callers of a function (by entry hex) in the current program.
// Args: [0] target entry hex (e.g. 0x27b798)

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

public class ListCallers extends GhidraScript {
	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		long t = Long.decode(args[0]);
		Address ta = toAddr(t);
		FunctionManager fm = currentProgram.getFunctionManager();
		Function tf = fm.getFunctionAt(ta);
		println("target: " + (tf == null ? "?? " : tf.getName()) + " @ " + ta);
		ReferenceManager rm = currentProgram.getReferenceManager();
		Reference[] refs = rm.getReferencesTo(ta);
		for (Reference r : refs) {
			Function caller = fm.getFunctionContaining(r.getFromAddress());
			println("caller: " + (caller == null ? "?" : caller.getName())
				+ " @ " + r.getFromAddress()
				+ (caller == null ? "" : " entry=" + caller.getEntryPoint())
				+ " type=" + r.getReferenceType());
		}
	}
}
