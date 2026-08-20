/* tests/vmdetect_probe.c — M1 最小验证: 只跑 vmdetect_scan 打印结果 */
#include <stdio.h>
#include "protect/vmdetect.h"

int main(void)
{
    prot_vmdetect_report r;
    prot_vmdetect_scan(&r);
    printf("cpu_hypervisor=%u hv_vendor=%u vm_processes=%u\n",
           r.cpu_hypervisor, r.hv_vendor, r.vm_processes);
    printf("suspicious=%u\n", prot_vmdetect_suspicious(&r));
    return 0;
}
