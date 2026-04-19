#!/system/bin/sh
set -u

TS="$(date +%Y%m%d_%H%M%S)"
OUT="wlan_diag_${TS}.log"

run() {
  echo "===== $* =====" >> "$OUT"
  sh -c "$*" >> "$OUT" 2>&1
  echo >> "$OUT"
}

echo "wlan diag start: $(date)" > "$OUT"
echo >> "$OUT"

run "uname -a"
run "cat /proc/version"
run "cat /proc/cmdline"
run "getprop ro.build.fingerprint"
run "getprop ro.boot.slot_suffix"
run "getprop ro.bootimage.build.fingerprint"
run "cat /proc/sys/kernel/random/boot_id"

run "zcat /proc/config.gz | grep -E 'CONFIG_(CNSS2|CNSS2_QMI|CNSS_UTILS|CNSS_GENL|WCNSS_MEM_PRE_ALLOC|QCA_CLD_WLAN|QCOM_QMI_HELPERS|IPA3|MODVERSIONS)='"

run "ls -l /vendor_dlkm/lib/modules 2>/dev/null | sed -n '1,200p'"
run "ls -l /system_dlkm/lib/modules 2>/dev/null | sed -n '1,200p'"

run "grep -R 'qmi_helpers\\|rmnet_ctl\\|ipa_fmwk\\|cnss_nl\\|cnss_prealloc\\|cnss_utils' /vendor/etc /odm/etc /system/etc 2>/dev/null"

for k in qmi_helpers rmnet_ctl ipa_fmwk cnss_nl cnss_prealloc cnss_utils wlan
do
  run "find /vendor_dlkm/lib/modules /system_dlkm/lib/modules -type f -name '*${k}*.ko' 2>/dev/null"
done

for f in \
  /vendor_dlkm/lib/modules/qmi_helpers.ko \
  /vendor_dlkm/lib/modules/rmnet_ctl.ko \
  /vendor_dlkm/lib/modules/ipa_fmwk.ko \
  /vendor_dlkm/lib/modules/cnss_nl.ko \
  /vendor_dlkm/lib/modules/cnss_prealloc.ko \
  /vendor_dlkm/lib/modules/cnss_utils.ko \
  /system_dlkm/lib/modules/qmi_helpers.ko \
  /system_dlkm/lib/modules/rmnet_ctl.ko \
  /system_dlkm/lib/modules/ipa_fmwk.ko \
  /system_dlkm/lib/modules/cnss_nl.ko \
  /system_dlkm/lib/modules/cnss_prealloc.ko \
  /system_dlkm/lib/modules/cnss_utils.ko
do
  if [ -f "$f" ]; then
    run "echo 'FILE: $f'; modinfo '$f' 2>/dev/null | grep -E '^(filename|name|vermagic|depends):' || strings '$f' | grep -m1 vermagic"
  fi
done

run "dmesg | grep -i 'version magic\\|module_layout\\|disagrees about version\\|qmi_helpers\\|rmnet_ctl\\|ipa_fmwk\\|cnss\\|wlan' | tail -n 400"
run "dmesg | tail -n 400"

echo "wlan diag end: $(date)" >> "$OUT"
echo "$OUT"