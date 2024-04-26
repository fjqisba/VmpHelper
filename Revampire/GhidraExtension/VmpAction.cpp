#include "VmpAction.h"
#include "../Ghidra/funcdata.hh"
#include "../Ghidra/coreaction.hh"
#include "../Helper/VmpBlockAnalyzer.h"
#include <set>

using namespace ghidra;


int4 ActionVmpStart::apply(Funcdata& data) {
	data.startVmpProcessing();
	return 0;
}

int4 ActionVmpHandlerDeadCode::apply(Funcdata& data)
{
    int4 i;
    list<PcodeOp*>::const_iterator iter;
    PcodeOp* op;
    Varnode* vn;
    uintb returnConsume;
    vector<Varnode*> worklist;
    VarnodeLocSet::const_iterator viter, endviter;
    const AddrSpaceManager* manage = data.getArch();
    AddrSpace* spc;

    // Clear consume flags
    for (viter = data.beginLoc(); viter != data.endLoc(); ++viter) {
        vn = *viter;
        vn->clearConsumeList();
        vn->clearConsumeVacuous();
        vn->setConsume(0);
        if (vn->isAddrForce() && (!vn->isDirectWrite()))
            vn->clearAddrForce();
    }

    // Set pre-live registers
    for (i = 0; i < manage->numSpaces(); ++i) {
        spc = manage->getSpace(i);
        if (spc == (AddrSpace*)0 || !spc->doesDeadcode()) continue;
        if (data.deadRemovalAllowed(spc)) continue; // Mark consumed if we have NOT heritaged
        viter = data.beginLoc(spc);
        endviter = data.endLoc(spc);
        while (viter != endviter) {
            vn = *viter++;
            ActionDeadCode::pushConsumed(~((uintb)0), vn, worklist);
        }
    }

    //返回都是全消费
    returnConsume = ~((uintb)0);

    for (iter = data.beginOpAlive(); iter != data.endOpAlive(); ++iter) {
        op = *iter;
        op->clearIndirectSource();
        if (op->isCall()) {
            // Postpone setting consumption on CALL and CALLIND inputs
            if (op->isCallWithoutSpec()) {
                for (i = 0; i < op->numInput(); ++i)
                    ActionDeadCode::pushConsumed(~((uintb)0), op->getIn(i), worklist);
            }
            if (!op->isAssignment())
                continue;
            if (op->holdOutput())
                ActionDeadCode::pushConsumed(~((uintb)0), op->getOut(), worklist);
        }
        else if (!op->isAssignment()) {
            OpCode opc = op->code();
            if (opc == CPUI_RETURN) {
                ActionDeadCode::pushConsumed(~((uintb)0), op->getIn(0), worklist);
                for (i = 1; i < op->numInput(); ++i)
                    ActionDeadCode::pushConsumed(returnConsume, op->getIn(i), worklist);
            }
            else if (opc == CPUI_BRANCHIND) {
                JumpTable* jt = data.findJumpTable(op);
                uintb mask;
                if (jt != (JumpTable*)0)
                    mask = jt->getSwitchVarConsume();
                else
                    mask = ~((uintb)0);
                ActionDeadCode::pushConsumed(mask, op->getIn(0), worklist);
            }
            else {
                for (i = 0; i < op->numInput(); ++i)
                    ActionDeadCode::pushConsumed(~((uintb)0), op->getIn(i), worklist);
            }
            // Postpone setting consumption on RETURN input
            continue;
        }
        else {
            for (i = 0; i < op->numInput(); ++i) {
                vn = op->getIn(i);
                if (vn->isAutoLive())
                    ActionDeadCode::pushConsumed(~((uintb)0), vn, worklist);
            }
        }
        vn = op->getOut();
        if (vn->isAutoLive()) {
            ActionDeadCode::pushConsumed(~((uintb)0), vn, worklist);
        }
        //增加对堆栈的处理
        else if (vn->getSpace() == data.getArch()->getStackSpace()) {
            ActionDeadCode::pushConsumed(~((uintb)0), vn, worklist);
        }
    }

    // Mark consumption of call parameters
    for (i = 0; i < data.numCalls(); ++i)
        ActionDeadCode::markConsumedParameters(data.getCallSpecs(i), worklist);

    // Propagate the consume flags
    while (!worklist.empty())
        ActionDeadCode::propagateConsumed(worklist);

    if (ActionDeadCode::lastChanceLoad(data, worklist)) {
        while (!worklist.empty())
            ActionDeadCode::propagateConsumed(worklist);
    }

    for (i = 0; i < manage->numSpaces(); ++i) {
        spc = manage->getSpace(i);
        if (spc == (AddrSpace*)0 || !spc->doesDeadcode()) continue;
        if (!data.deadRemovalAllowed(spc)) continue; // Don't eliminate if we haven't heritaged
        viter = data.beginLoc(spc);
        endviter = data.endLoc(spc);
        int4 changecount = 0;
        while (viter != endviter) {
            vn = *viter++;		// Advance iterator BEFORE (possibly) deleting varnode
            if (!vn->isWritten()) continue;
            bool vacflag = vn->isConsumeVacuous();
            vn->clearConsumeList();
            vn->clearConsumeVacuous();
            if (!vacflag) {		// Not even vacuously consumed
                op = vn->getDef();
                changecount += 1;
                if (op->isCall())
                    data.opUnsetOutput(op); // For calls just get rid of output
                else
                    data.opDestroy(op);	// Otherwise completely remove the op
            }
            else {
                // Check for values that are never used, but bang around
                // for a while
                if (vn->getConsume() == 0) {
                    if (ActionDeadCode::neverConsumed(vn, data))
                        changecount += 1;
                }
            }
        }
        if (changecount != 0)
            data.seenDeadcode(spc);	// Record that we have seen dead code for this space
    }
    data.clearDeadVarnodes();
    data.clearDeadOps();
    return 0;
}


int4 ActionFixStack::apply(Funcdata& data)
{
	DeepStackFix fixStack;
	return fixStack.FixAllRam(&data);
}