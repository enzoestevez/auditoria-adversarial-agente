"""Control de reproducibilidad: el sistema SIN ningun ataque.

Uso:
    python src/control.py                  # 10 avisos, 3 repeticiones
    python src/control.py --avisos 20 --repeticiones 3

================================================================================
POR QUE ESTE CONTROL ES EL EXPERIMENTO MAS IMPORTANTE DE LA AUDITORIA

La bateria de ataques midio que, con `temperature=0`, **14 de 19 ataques
produjeron extracciones distintas entre repeticiones de la entrada identica**. Y
paso tambien en ataques que FALLARON: `ev-02` vario el `organismo`,
`fp-01` vario el `objeto`. O sea que la variabilidad no la causa el ataque.

Pero todos esos documentos estaban modificados. Este control responde la pregunta
que queda: **¿el sistema es reproducible sobre avisos limpios?**

Si la respuesta es que no, el hallazgo deja de ser sobre seguridad y pasa a ser
sobre la validez de todo el proyecto 02, que reporto "15 de 95 avisos con la
fecha de apertura vencida" desde UNA sola corrida, sin control de
reproducibilidad.

En un sistema cuya salida es una acusacion contra un organismo del Estado:
**una acusacion que no se puede reproducir no se puede defender.** Si el organismo
pide que se vuelva a correr y el hallazgo no aparece, el hallazgo no existia.

================================================================================
QUE MIDE, EXACTAMENTE

Tres niveles, de lo mas fino a lo que de verdad importa:

  1. EXTRACCION   ¿los nueve campos salieron identicos en las k repeticiones?
  2. DECISION     ¿aprobado/escalado/sin_llave fue el mismo?
  3. HALLAZGO     ¿el conjunto de discrepancias reportadas fue el mismo?

El nivel 3 es el que decide si el proyecto 02 es defendible. Los campos pueden
bailar en `objeto` sin consecuencia; si baila `fecha_apertura`, se mueve el
numero que el proyecto publica.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "sistema"))

import agente  # noqa: E402
import comun  # noqa: E402

BASE = RAIZ / "data" / "base"
REPORTES = RAIZ / "reports"


def main() -> None:
    ap = argparse.ArgumentParser(description="¿Es reproducible el agente sin ataques?")
    ap.add_argument("--avisos", type=int, default=10)
    ap.add_argument("--repeticiones", type=int, default=3)
    ap.add_argument("--presupuesto", type=float, default=0.50)
    args = ap.parse_args()

    agente.cargar_env()
    if not os.environ.get("GOOGLE_API_KEY"):
        sys.exit("Falta GOOGLE_API_KEY en .env")
    try:
        import google.genai  # noqa: F401
    except ImportError:
        sys.exit("Falta google-genai: .venv\\Scripts\\python.exe -m pip install -r requirements.txt")

    base = {}
    for l in (BASE / "traza-reproceso.jsonl").read_text(encoding="utf-8").splitlines():
        if l.strip():
            r = json.loads(l)
            base[r["aviso"]] = r
    meta = {r["id"]: r for r in json.loads((BASE / "indice_p01.json").read_text(encoding="utf-8"))}
    idx = comun.cargar_registro()

    # Se eligen avisos APROBADOS: son los unicos donde el sistema llega a
    # reportar hallazgos, y por lo tanto los unicos donde la irreproducibilidad
    # tiene consecuencia publicable. Orden determinista para que el control sea
    # repetible.
    elegidos = [a for a in sorted(base) if base[a]["decision"] == "aprobado"][: args.avisos]
    print(f"control de reproducibilidad · {len(elegidos)} avisos LIMPIOS × "
          f"{args.repeticiones} repeticiones")
    print(f"sin ninguna mutación · temperature=0 · modelo {agente.MODELO}\n")

    salida, gastado = [], 0.0
    for n, doc_id in enumerate(elegidos, 1):
        texto = (BASE / "avisos" / meta[doc_id]["txt"]).read_text(encoding="utf-8")
        repes = []
        for _ in range(args.repeticiones):
            if gastado + 0.01 > args.presupuesto:
                break
            r = agente.extraer_con_reintentos(texto, verboso=False)
            caso = {"aviso": doc_id, "modelo": agente.MODELO,
                    "tokens_in": r["tokens_in"], "tokens_out": r["tokens_out"],
                    "latencia_ms": r["ms"],
                    "costo_usd": round(agente.costo(r["tokens_in"], r["tokens_out"]), 6)}
            gastado += caso["costo_usd"]
            if r["error"]:
                repes.append({"decision": "error_extraccion", "motivo": r["error"],
                              "extraido": None, "discrepancias": None})
                continue
            d = agente.decidir(caso, r["datos"], meta[doc_id]["publicado_desde"],
                               idx, comun.UMBRAL)
            repes.append({"decision": d.get("decision"), "extraido": d.get("extraido"),
                          "discrepancias": sorted(d.get("discrepancias") or []),
                          "proceso": d.get("proceso")})
        if not repes:
            break

        ex = {json.dumps(x["extraido"], sort_keys=True, ensure_ascii=False) for x in repes}
        de = {x["decision"] for x in repes}
        ha = {json.dumps(x["discrepancias"], ensure_ascii=False) for x in repes}
        campos = set()
        if len(ex) > 1:
            ds = [json.loads(e) for e in ex]
            for c in ds[0] or {}:
                if len({json.dumps(d.get(c), ensure_ascii=False) for d in ds}) > 1:
                    campos.add(c)
        reg = {
            "aviso": doc_id, "repeticiones": len(repes),
            "extraccion_identica": len(ex) == 1,
            "decision_identica": len(de) == 1,
            "hallazgo_identico": len(ha) == 1,
            "campos_que_variaron": sorted(campos),
            "discrepancias_por_repeticion": [x["discrepancias"] for x in repes],
            "limpio_de_referencia": sorted(base[doc_id].get("discrepancias") or []),
            "repes": repes,
            "cuando": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        salida.append(reg)
        marca = ("idéntico" if reg["extraccion_identica"]
                 else f"varió: {','.join(reg['campos_que_variaron'])}")
        alarma = "" if reg["hallazgo_identico"] else "   <-- EL HALLAZGO CAMBIÓ"
        print(f"  {n}/{len(elegidos)}  {doc_id:11} {marca[:52]:54}{alarma}")

    REPORTES.mkdir(exist_ok=True)
    with (REPORTES / "control-determinismo.jsonl").open("a", encoding="utf-8") as f:
        for r in salida:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    n = len(salida)
    if not n:
        sys.exit("\nNo se procesó ningún aviso.")
    ident = sum(r["extraccion_identica"] for r in salida)
    dec = sum(r["decision_identica"] for r in salida)
    hal = sum(r["hallazgo_identico"] for r in salida)

    print(f"\n{'='*70}")
    print(f"REPRODUCIBILIDAD SIN ATAQUES · {n} avisos × {args.repeticiones} repeticiones")
    print(f"{'='*70}\n")
    print(f"  extracción idéntica en todas las repeticiones   {ident}/{n}  {ident/n:.0%}")
    print(f"  decisión idéntica                               {dec}/{n}  {dec/n:.0%}")
    print(f"  HALLAZGOS idénticos                             {hal}/{n}  {hal/n:.0%}")

    vc = Counter(c for r in salida for c in r["campos_que_variaron"])
    if vc:
        print("\n  campos que variaron, por frecuencia:")
        for c, k in vc.most_common():
            print(f"    {c:22} {k}/{n} avisos")

    cambiaron = [r for r in salida if not r["hallazgo_identico"]]
    if cambiaron:
        print(f"\n  !! {len(cambiaron)} aviso(s) reportaron hallazgos DISTINTOS entre "
              f"repeticiones de la misma entrada:")
        for r in cambiaron:
            print(f"      {r['aviso']}: {r['discrepancias_por_repeticion']}")
        print("\n  Eso significa que el número que publica el proyecto 02 —cuántos")
        print("  avisos tienen la fecha de apertura vencida— se mueve entre corridas.")
        print("  Una acusación que no se puede reproducir no se puede defender.")
    else:
        print("\n  Ningún hallazgo cambió entre repeticiones: a nivel de lo que el")
        print("  sistema REPORTA, fue reproducible en esta muestra. La variación de")
        print("  campos que no entran en la comparación no tiene consecuencia")
        print("  publicable, y decirlo así es más honesto que alarmar por el 74%.")

    print(f"\nGastado USD {gastado:.4f} · reports/control-determinismo.jsonl")


if __name__ == "__main__":
    main()
