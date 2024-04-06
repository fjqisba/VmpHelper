#include "VmpFunction.h"
#include <graph.hpp>

VmpFunction::VmpFunction(VmpArchitecture* glb):arch(glb)
{
	
}

VmpFunction::~VmpFunction()
{

}

VmpArchitecture* VmpFunction::Arch()
{
    return arch;
}

void VmpFunction::CreateGraph()
{
    qstring graphTitle;
    graphTitle.sprnt("vmp_%a", startAddr);
    std::vector<std::string> textData;
    TWidget* widget = find_widget(graphTitle.c_str());
    if (widget) {
        display_widget(widget, 0x0);
        return;
    }
    netnode id;
    qstring strNodeId = qstring("$ ") + graphTitle;
    if (!id.create(strNodeId.c_str())) {
        id.kill();
    }
    graph_viewer_t* gv = create_graph_viewer(graphTitle.c_str(), id, VmpControlFlowShowGraph::graph_callback, &cfg.graph, 0);
    display_widget(gv, WOPN_DP_TAB);
    viewer_fit_window(gv);
}

void VmpFunction::FollowVmp(size_t start)
{
    startAddr = start;
    //ÒÑÉú³Éblocks
    if (cfg.blocksMap.size()) {
        return;
    }
	VmpControlFlowBuilder builder(*this);
	builder.BuildCFG(startAddr);
}