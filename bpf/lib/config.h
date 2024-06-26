/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */

#pragma once

/* Subset of kernel's include/linux/kconfig.h */

#define __ARG_PLACEHOLDER_1 0,
#define __take_second_arg(__ignored, val, ...) val

#define __is_defined(x)              ___is_defined(x)
#define ___is_defined(val)           ____is_defined(__ARG_PLACEHOLDER_##val)
#define ____is_defined(arg1_or_junk) __take_second_arg(arg1_or_junk 1, 0)

#define is_defined(option)           __is_defined(option)

#define __must_check		     __attribute__((warn_unused_result))
