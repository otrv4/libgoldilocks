/**
 * EdDSA crypto routines, metaheader.
 */

$("\n".join([
    "#include <decaf/eddsa_%s.hxx>" % g for g in sorted([c["bits"] for _,c in curve.iteritems()])
]))
