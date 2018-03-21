/** Master header for Goldilocks library, C++ version. */

$("\n".join([
    "#include <goldilocks/ed%s.hxx>" % g for g in sorted([c["bits"] for _,c in curve.items()])
]))

/** Namespace for all C++ goldilocks objects. */
namespace goldilocks {
    /** Given a template with a "run" function, run it for all curves */
    template <template<typename Group> class Run>
    void run_for_all_curves() {
$("\n".join([
"        Run<%s>::run();" % cd["cxx_ns"]
for cd in sorted(curve.values(), key=lambda x:x["c_ns"])
])
)
    }
}
