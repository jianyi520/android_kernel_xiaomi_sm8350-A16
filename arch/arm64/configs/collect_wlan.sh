#!/system/bin/sh
TS=$(date +%Y%m%d_%H%M%S)
OUT="module_path_${TS}.log"

echo "=== start: $(date) ===" > "$OUT"
echo "=== uname ===" >> "$OUT"
uname -a >> "$OUT" 2>&1
echo >> "$OUT"

echo "=== grep module load clues ===" >> "$OUT"
grep -R "qmi_helpers\.ko\|rmnet_ctl\.ko\|ipa_fmwk\.ko\|cnss" \
  /vendor/etc /odm/etc /system/etc \
  /vendor/lib/modules /system/lib/modules /system_dlkm/lib/modules \
  >> "$OUT" 2>&1
echo >> "$OUT"

echo "=== direct find ko ===" >> "$OUT"
find /vendor /odm /system /system_dlkm -type f \
  \( -name "*qmi_helpers*.ko" -o -name "*rmnet_ctl*.ko" -o -name "*ipa_fmwk*.ko" -o -name "*cnss*.ko" \) \
  >> "$OUT" 2>&1
echo >> "$OUT"

echo "=== dmesg key lines ===" >> "$OUT"
dmesg | grep -i "version magic\|module_layout\|disagrees about version\|qmi_helpers\|rmnet_ctl\|ipa_fmwk\|cnss" \
  >> "$OUT" 2>&1
echo >> "$OUT"

echo "=== end: $(date) ===" >> "$OUT"
echo "$OUT"