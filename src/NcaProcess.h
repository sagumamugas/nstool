#pragma once
#include "types.h"
#include "FsProcess.h"

#include <pietendo/hac/fileformat/NcaFileFormat.h>
#include <pietendo/hac/KeyBag.h>
#include <pietendo/hac/ContentArchiveHeader.h>
#include <pietendo/hac/HierarchicalIntegrityHeader.h>
#include <pietendo/hac/HierarchicalSha256Header.h>

namespace nstool {

class NcaProcess
{
public:
	NcaProcess();

	void process();

	// generic
	void setInputFile(const std::shared_ptr<tc::io::IStream>& file);
	void setKeyCfg(const pie::hac::KeyBag& keycfg);
	void setCliOutputMode(CliOutputMode type);
	void setVerifyMode(bool verify);
	void setBaseNCAPath(const tc::Optional<tc::io::Path>& keycfg);


	// fs specific
	void setShowFsTree(bool show_fs_tree);
	void setFsRootLabel(const std::string& root_label);
	void setExtractJobs(const std::vector<nstool::ExtractJob>& extract_jobs);

	// post process() get FS out
	const std::shared_ptr<tc::io::IFileSystem>& getFileSystem() const;
private:
	const std::string kNpdmExefsPath = "/main.npdm";

	std::string mModuleName;

	// user options
	std::shared_ptr<tc::io::IStream> mFile;
	pie::hac::KeyBag mKeyCfg;
	CliOutputMode mCliOutputMode;
	bool mVerify;
	tc::Optional<tc::io::Path> baseNcaPath;

	// fs processing
	std::shared_ptr<tc::io::IFileSystem> mFileSystem;
	FsProcess mFsProcess;

	// nca data
	std::shared_ptr<pie::hac::NcaFileFormat> mNca;

	void displayHeader();
	void processPartitions();

	NcaProcess readBaseNCA();

	std::string getContentTypeForMountStr(pie::hac::nca::ContentType cont_type) const;
};

}