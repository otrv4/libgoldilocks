/** Master header for Decaf library, C++ version. */

$("\n".join([
    "#include <decaf/point_%s.hxx>" % g for g in sorted([c["bits"] for _,c in curve.iteritems()])
]))

namespace decaf {
    template <template<typename Group> class Run>
    void run_for_all_curves() {
$("\n".join([
"        Run<%s>::run();" % cd["cxx_ns"]
for cd in sorted(curve.values(), key=lambda x:x["c_ns"])
])
)
    }
}
