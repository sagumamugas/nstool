#include "MetaProcess.h"

#include <pietendo/hac/AccessControlInfoUtil.h>
#include <pietendo/hac/FileSystemAccessUtil.h>
#include <pietendo/hac/KernelCapabilityUtil.h>
#include <pietendo/hac/MetaUtil.h>

nstool::MetaProcess::MetaProcess() :
	mModuleName("nstool::MetaProcess"),
	mCliOutputMode(true, false, false, false),
	mVerify(false)
{
}

void nstool::MetaProcess::process()
{
	mMeta = pie::hac::MetaFileFormat(mFile, mKeyCfg);

	if (mVerify)
	{
		mMeta.validate();
	}

	if (mCliOutputMode.show_basic_info)
	{
		const pie::hac::Meta& meta = this->mMeta.getMeta();
		// npdm binary
		displayMetaHeader(meta);

		// aci binary
		displayAciHdr(meta.getAccessControlInfo());
		displayFac(meta.getAccessControlInfo().getFileSystemAccessControl());
		displaySac(meta.getAccessControlInfo().getServiceAccessControl());
		displayKernelCap(meta.getAccessControlInfo().getKernelCapabilities());

		// acid binary
		if (mCliOutputMode.show_extended_info)
		{
			displayAciDescHdr(meta.getAccessControlInfoDesc());
			displayFac(meta.getAccessControlInfoDesc().getFileSystemAccessControl());
			displaySac(meta.getAccessControlInfoDesc().getServiceAccessControl());
			displayKernelCap(meta.getAccessControlInfoDesc().getKernelCapabilities());
		}
	}
}

void nstool::MetaProcess::setInputFile(const std::shared_ptr<tc::io::IStream>& file)
{
	mFile = file;
}

void nstool::MetaProcess::setKeyCfg(const pie::hac::KeyBag& keycfg)
{
	mKeyCfg = keycfg;
}

void nstool::MetaProcess::setCliOutputMode(CliOutputMode type)
{
	mCliOutputMode = type;
}

void nstool::MetaProcess::setVerifyMode(bool verify)
{
	mVerify = verify;
}

void nstool::MetaProcess::displayMetaHeader(const pie::hac::Meta& hdr)
{
	fmt::print("[Meta Header]\n");
	fmt::print("  ACID KeyGeneration: {:d}\n", hdr.getAccessControlInfoDescKeyGeneration());
	fmt::print("  Flags:\n");
	fmt::print("    Is64BitInstruction:       {}\n", hdr.getIs64BitInstructionFlag());
	fmt::print("    ProcessAddressSpace:      {:s}\n", pie::hac::MetaUtil::getProcessAddressSpaceAsString(hdr.getProcessAddressSpace()));
	fmt::print("    OptimizeMemoryAllocation: {}\n", hdr.getOptimizeMemoryAllocationFlag());
	fmt::print("  SystemResourceSize: 0x{:x}\n", hdr.getSystemResourceSize());
	fmt::print("  Main Thread Params:\n");
	fmt::print("    Priority:      {:d}\n", hdr.getMainThreadPriority());
	fmt::print("    CpuId:         {:d}\n", hdr.getMainThreadCpuId());
	fmt::print("    StackSize:     0x{:x}\n", hdr.getMainThreadStackSize());
	fmt::print("  TitleInfo:\n");
	fmt::print("    Version:       v{:d}\n", hdr.getVersion());
	fmt::print("    Name:          {:s}\n", hdr.getName());
	if (hdr.getProductCode().length())
	{
		fmt::print("    ProductCode:   {:s}\n", hdr.getProductCode());
	}
}

void nstool::MetaProcess::displayAciHdr(const pie::hac::AccessControlInfo& aci)
{
	fmt::print("[Access Control Info]\n");
	fmt::print("  ProgramID:       0x{:016x}\n", aci.getProgramId());
}

void nstool::MetaProcess::displayAciDescHdr(const pie::hac::AccessControlInfoDesc& acid)
{
	fmt::print("[Access Control Info Desc]\n");
	fmt::print("  Flags:           \n");
	fmt::print("    Production:            {}\n", acid.getProductionFlag());
	fmt::print("    Unqualified Approval:  {}\n", acid.getUnqualifiedApprovalFlag());
	fmt::print("    Memory Region:         {:s} ({:d})\n", pie::hac::AccessControlInfoUtil::getMemoryRegionAsString(acid.getMemoryRegion()), (uint32_t)acid.getMemoryRegion());
	fmt::print("  ProgramID Restriction\n");
	fmt::print("    Min:           0x{:016x}\n", acid.getProgramIdRestrict().min);
	fmt::print("    Max:           0x{:016x}\n", acid.getProgramIdRestrict().max);
}

void nstool::MetaProcess::displayFac(const pie::hac::FileSystemAccessControl& fac)
{
	fmt::print("[FS Access Control]\n");
	fmt::print("  Format Version:  {:d}\n", fac.getFormatVersion());

	if (fac.getFsAccess().size())
	{
		std::vector<std::string> fs_access_str_list;
		for (auto itr = fac.getFsAccess().begin(); itr != fac.getFsAccess().end(); itr++)
		{
			std::string flag_string = pie::hac::FileSystemAccessUtil::getFsAccessFlagAsString(pie::hac::fac::FsAccessFlag(*itr));
			if (mCliOutputMode.show_extended_info)
			{
				fs_access_str_list.push_back(fmt::format("{:s} (bit {:d})", flag_string, (uint32_t)*itr));
			}
			else
			{
				fs_access_str_list.push_back(flag_string);
			}
			
		}

		fmt::print("  FsAccess:\n");
		fmt::print("{:s}", tc::cli::FormatUtil::formatListWithLineLimit(fs_access_str_list, 60, 4));
	}
	
	if (fac.getContentOwnerIdList().size())
	{
		fmt::print("  Content Owner IDs:\n");
		for (size_t i = 0; i < fac.getContentOwnerIdList().size(); i++)
		{
			fmt::print("    0x{:016x}\n", fac.getContentOwnerIdList()[i]);
		}
	}

	if (fac.getSaveDataOwnerIdList().size())
	{
		fmt::print("  Save Data Owner IDs:\n");
		for (size_t i = 0; i < fac.getSaveDataOwnerIdList().size(); i++)
		{
			fmt::print("    0x{:016x} ({:s})\n", fac.getSaveDataOwnerIdList()[i].id, pie::hac::FileSystemAccessUtil::getSaveDataOwnerAccessModeAsString(fac.getSaveDataOwnerIdList()[i].access_type));
		}
	}
}

void nstool::MetaProcess::displaySac(const pie::hac::ServiceAccessControl& sac)
{
	fmt::print("[Service Access Control]\n");
	fmt::print("  Service List:\n");
	std::vector<std::string> service_name_list;
	for (size_t i = 0; i < sac.getServiceList().size(); i++)
	{
		service_name_list.push_back(sac.getServiceList()[i].getName() + (sac.getServiceList()[i].isServer() ? "(isSrv)" : ""));
	}
	fmt::print("{:s}", tc::cli::FormatUtil::formatListWithLineLimit(service_name_list, 60, 4));
}

void nstool::MetaProcess::displayKernelCap(const pie::hac::KernelCapabilityControl& kern)
{
	fmt::print("[Kernel Capabilities]\n");
	if (kern.getThreadInfo().isSet())
	{
		pie::hac::ThreadInfoHandler threadInfo = kern.getThreadInfo();
		fmt::print("  Thread Priority:\n");
		fmt::print("    Min:     {:d}\n", threadInfo.getMinPriority());
		fmt::print("    Max:     {:d}\n", threadInfo.getMaxPriority());
		fmt::print("  CpuId:\n");
		fmt::print("    Min:     {:d}\n", threadInfo.getMinCpuId());
		fmt::print("    Max:     {:d}\n", threadInfo.getMaxCpuId());
	}

	if (kern.getSystemCalls().isSet())
	{
		auto syscall_ids = kern.getSystemCalls().getSystemCallIds();
		fmt::print("  SystemCalls:\n");
		std::vector<std::string> syscall_names;
		for (size_t syscall_id = 0; syscall_id < syscall_ids.size(); syscall_id++)
		{
			if (syscall_ids.test(syscall_id))
				syscall_names.push_back(pie::hac::KernelCapabilityUtil::getSystemCallIdAsString(pie::hac::kc::SystemCallId(syscall_id)));
		}
		fmt::print("{:s}", tc::cli::FormatUtil::formatListWithLineLimit(syscall_names, 60, 4));
	}
	if (kern.getMemoryMaps().isSet())
	{
		auto maps = kern.getMemoryMaps().getMemoryMaps();
		auto ioMaps = kern.getMemoryMaps().getIoMemoryMaps();

		fmt::print("  MemoryMaps:\n");
		for (size_t i = 0; i < maps.size(); i++)
		{
			fmt::print("    {:s}\n", formatMappingAsString(maps[i]));	
		}
		//fmt::print("  IoMaps:\n");
		for (size_t i = 0; i < ioMaps.size(); i++)
		{
			fmt::print("    {:s}\n", formatMappingAsString(ioMaps[i]));
		}
	}
	if (kern.getInterupts().isSet())
	{
		std::vector<std::string> interupts;
		for (auto itr = kern.getInterupts().getInteruptList().begin(); itr != kern.getInterupts().getInteruptList().end(); itr++)
		{
			interupts.push_back(fmt::format("0x{:x}", *itr));
		}
		fmt::print("  Interupts Flags:\n");
		fmt::print("{:s}", tc::cli::FormatUtil::formatListWithLineLimit(interupts, 60, 4));
	}
	if (kern.getMiscParams().isSet())
	{
		fmt::print("  ProgramType:        {:s} ({:d})\n", pie::hac::KernelCapabilityUtil::getProgramTypeAsString(kern.getMiscParams().getProgramType()), (uint32_t)kern.getMiscParams().getProgramType());
	}
	if (kern.getKernelVersion().isSet())
	{
		fmt::print("  Kernel Version:     {:d}.{:d}\n", kern.getKernelVersion().getVerMajor(), kern.getKernelVersion().getVerMinor());
	}
	if (kern.getHandleTableSize().isSet())
	{
		fmt::print("  Handle Table Size:  0x{:x}\n", kern.getHandleTableSize().getHandleTableSize());
	}
	if (kern.getMiscFlags().isSet())
	{
		auto misc_flags = kern.getMiscFlags().getMiscFlags();
		fmt::print("  Misc Flags:\n");
		std::vector<std::string> misc_flags_names;
		for (size_t misc_flags_bit = 0; misc_flags_bit < misc_flags.size(); misc_flags_bit++)
		{
			if (misc_flags.test(misc_flags_bit))
				misc_flags_names.push_back(pie::hac::KernelCapabilityUtil::getMiscFlagsBitAsString(pie::hac::kc::MiscFlagsBit(misc_flags_bit)));
		}
		fmt::print("{:s}", tc::cli::FormatUtil::formatListWithLineLimit(misc_flags_names, 60, 4));
	}
}

std::string nstool::MetaProcess::formatMappingAsString(const pie::hac::MemoryMappingHandler::sMemoryMapping& map) const
{
	return fmt::format("0x{:016x} - 0x{:016x} (perm={:s}) (type={:s})", ((uint64_t)map.addr << 12), (((uint64_t)(map.addr + map.size) << 12) - 1), pie::hac::KernelCapabilityUtil::getMemoryPermissionAsString(map.perm), pie::hac::KernelCapabilityUtil::getMappingTypeAsString(map.type));
}