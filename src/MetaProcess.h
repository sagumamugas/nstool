#pragma once
#include "types.h"

#include <pietendo/hac/fileformat/MetaFileFormat.h>
#include <pietendo/hac/KeyBag.h>

namespace nstool {

class MetaProcess
{
public:
	MetaProcess();

	void process();

	void setInputFile(const std::shared_ptr<tc::io::IStream>& file);
	void setKeyCfg(const pie::hac::KeyBag& keycfg);
	void setCliOutputMode(CliOutputMode type);
	void setVerifyMode(bool verify);

private:
	std::string mModuleName;

	std::shared_ptr<tc::io::IStream> mFile;
	pie::hac::KeyBag mKeyCfg;
	CliOutputMode mCliOutputMode;
	bool mVerify;

	pie::hac::MetaFileFormat mMeta;

	void displayMetaHeader(const pie::hac::Meta& hdr);
	void displayAciHdr(const pie::hac::AccessControlInfo& aci);
	void displayAciDescHdr(const pie::hac::AccessControlInfoDesc& aci);
	void displayFac(const pie::hac::FileSystemAccessControl& fac);
	void displaySac(const pie::hac::ServiceAccessControl& sac);
	void displayKernelCap(const pie::hac::KernelCapabilityControl& kern);

	std::string formatMappingAsString(const pie::hac::MemoryMappingHandler::sMemoryMapping& map) const;
};

}