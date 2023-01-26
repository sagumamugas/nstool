#include "NcaProcess.h"
#include "MetaProcess.h"
#include "util.h"

#include <pietendo/hac/ContentArchiveUtil.h>
#include <pietendo/hac/AesKeygen.h>
#include <pietendo/hac/HierarchicalSha256Stream.h>
#include <pietendo/hac/HierarchicalIntegrityStream.h>
#include <pietendo/hac/BKTREncryptedStream.h>
#include <pietendo/hac/PartitionFsSnapshotGenerator.h>
#include <pietendo/hac/RomFsSnapshotGenerator.h>
#include <pietendo/hac/CombinedFsSnapshotGenerator.h>

nstool::NcaProcess::NcaProcess() :
	mModuleName("nstool::NcaProcess"),
	mFile(),
	mCliOutputMode(true, false, false, false),
	mVerify(false),
	mFileSystem(),
	mFsProcess()
{
}

void nstool::NcaProcess::process()
{
	mNca = std::make_shared<pie::hac::NcaFileFormat>(mFile, mKeyCfg);

	// validate signatures
	if (mVerify)
		mNca->validate();

	// display header
	if (mCliOutputMode.show_basic_info)
		displayHeader();

	// process partition
	processPartitions();
}

void nstool::NcaProcess::setInputFile(const std::shared_ptr<tc::io::IStream>& file)
{
	mFile = file;
}

void nstool::NcaProcess::setBaseNCAPath(const tc::Optional<tc::io::Path>& baseNCA)
{
	baseNcaPath = baseNCA;
}

void nstool::NcaProcess::setKeyCfg(const pie::hac::KeyBag& keycfg)
{
	mKeyCfg = keycfg;
}

void nstool::NcaProcess::setCliOutputMode(CliOutputMode type)
{
	mCliOutputMode = type;
}

void nstool::NcaProcess::setVerifyMode(bool verify)
{
	mVerify = verify;
}

void nstool::NcaProcess::setShowFsTree(bool show_fs_tree)
{
	mFsProcess.setShowFsTree(show_fs_tree);
}

void nstool::NcaProcess::setFsRootLabel(const std::string& root_label)
{
	mFsProcess.setFsRootLabel(root_label);
}

void nstool::NcaProcess::setExtractJobs(const std::vector<nstool::ExtractJob>& extract_jobs)
{
	mFsProcess.setExtractJobs(extract_jobs);
}

const std::shared_ptr<tc::io::IFileSystem>& nstool::NcaProcess::getFileSystem() const
{
	return mFileSystem;
}

nstool::NcaProcess nstool::NcaProcess::readBaseNCA() {
	if (baseNcaPath.isNull()) {
		throw tc::Exception(mModuleName, "Base NCA not supplied. Necessary for update NCA.");
	}
	std::shared_ptr<tc::io::IStream> base_stream = std::make_shared<tc::io::FileStream>(tc::io::FileStream(baseNcaPath.get(), tc::io::FileMode::Open, tc::io::FileAccess::Read));

	NcaProcess obj;
	nstool::CliOutputMode cliOutput;
	cliOutput.show_basic_info = false;
	cliOutput.show_extended_info = false;
	cliOutput.show_keydata = false;
	cliOutput.show_layout = false;
	obj.setCliOutputMode(cliOutput);
	obj.setVerifyMode(true);
	obj.setKeyCfg(mKeyCfg);
	obj.setInputFile(base_stream);
	obj.process();
	return obj;
}

void nstool::NcaProcess::displayHeader()
{
	const pie::hac::ContentArchiveHeader& mHdr = mNca->getHeader();
	fmt::print("[NCA Header]\n");
	fmt::print("  Format Type:     {:s}\n", pie::hac::ContentArchiveUtil::getFormatHeaderVersionAsString((pie::hac::nca::HeaderFormatVersion)mHdr.getFormatVersion()));
	fmt::print("  Dist. Type:      {:s}\n", pie::hac::ContentArchiveUtil::getDistributionTypeAsString(mHdr.getDistributionType()));
	fmt::print("  Content Type:    {:s}\n", pie::hac::ContentArchiveUtil::getContentTypeAsString(mHdr.getContentType()));
	fmt::print("  Key Generation:  {:d}\n", mHdr.getKeyGeneration());
	fmt::print("  Sig. Generation: {:d}\n", mHdr.getSignatureKeyGeneration());
	fmt::print("  Kaek Index:      {:s} ({:d})\n", pie::hac::ContentArchiveUtil::getKeyAreaEncryptionKeyIndexAsString((pie::hac::nca::KeyAreaEncryptionKeyIndex)mHdr.getKeyAreaEncryptionKeyIndex()), mHdr.getKeyAreaEncryptionKeyIndex());
	fmt::print("  Size:            0x{:x}\n", mHdr.getContentSize());
	fmt::print("  ProgID:          0x{:016x}\n", mHdr.getProgramId());
	fmt::print("  Content Index:   {:d}\n", mHdr.getContentIndex());
	fmt::print("  SdkAddon Ver.:   {:s} (v{:d})\n", pie::hac::ContentArchiveUtil::getSdkAddonVersionAsString(mHdr.getSdkAddonVersion()), mHdr.getSdkAddonVersion());
	if (mHdr.hasRightsId())
	{
		fmt::print("  RightsId:        {:s}\n", tc::cli::FormatUtil::formatBytesAsString(mHdr.getRightsId().data(), mHdr.getRightsId().size(), true, ""));
	}

	const pie::hac::NcaFileFormat::sKeys& mContentKey = mNca->getContentKey();
	
	if (mContentKey.kak_list.size() > 0 && mCliOutputMode.show_keydata)
	{
		fmt::print("  Key Area:\n");
		fmt::print("    <--------------------------------------------------------------------------------------------------------->\n");
		fmt::print("    | IDX | ENCRYPTED KEY                                   | DECRYPTED KEY                                   |\n");
		fmt::print("    |-----|-------------------------------------------------|-------------------------------------------------|\n");
		for (size_t i = 0; i < mContentKey.kak_list.size(); i++)
		{
			fmt::print("    | {:3d} | {:s} | ", mContentKey.kak_list[i].index, tc::cli::FormatUtil::formatBytesAsString(mContentKey.kak_list[i].enc.data(), mContentKey.kak_list[i].enc.size(), true, ""));
						
			
			if (mContentKey.kak_list[i].decrypted)
				fmt::print("{:s}", tc::cli::FormatUtil::formatBytesAsString(mContentKey.kak_list[i].dec.data(), mContentKey.kak_list[i].dec.size(), true, ""));
			else
				fmt::print("<unable to decrypt>                            ");
			
			fmt::print(" |\n");
		}
		fmt::print("    <--------------------------------------------------------------------------------------------------------->\n");
	}

	if (mCliOutputMode.show_layout)
	{
		fmt::print("  Partitions:\n");
		for (size_t i = 0; i < mHdr.getPartitionEntryList().size(); i++)
		{
			uint32_t index = mHdr.getPartitionEntryList()[i].header_index;
			const pie::hac::NcaFileFormat::sPartitionInfo& info = mNca->getPartition(index);
			if (info.size == 0) continue;

			fmt::print("    {:d}:\n", index);
			fmt::print("      Offset:      0x{:x}\n", info.offset);
			fmt::print("      Size:        0x{:x}\n", info.size);
			fmt::print("      Format Type: {:s}\n", pie::hac::ContentArchiveUtil::getFormatTypeAsString(info.format_type));
			fmt::print("      Hash Type:   {:s}\n", pie::hac::ContentArchiveUtil::getHashTypeAsString(info.hash_type));
			fmt::print("      Enc. Type:   {:s}\n", pie::hac::ContentArchiveUtil::getEncryptionTypeAsString(info.enc_type));
			if (info.enc_type == pie::hac::nca::EncryptionType_AesCtr)
			{
				pie::hac::detail::aes_iv_t aes_ctr;
				memcpy(aes_ctr.data(), info.aes_ctr.data(), aes_ctr.size());
				tc::crypto::IncrementCounterAes128Ctr(aes_ctr.data(), info.offset>>4);
				fmt::print("      AesCtr Counter:\n");
				fmt::print("        {:s}\n", tc::cli::FormatUtil::formatBytesAsString(aes_ctr.data(), aes_ctr.size(), true, ""));
			}
			if (info.hash_type == pie::hac::nca::HashType_HierarchicalIntegrity)
			{
				auto hash_hdr = info.hierarchicalintegrity_hdr;
				fmt::print("      HierarchicalIntegrity Header:\n");
				for (size_t j = 0; j < hash_hdr.getLayerInfo().size(); j++)
				{
					if (j+1 == hash_hdr.getLayerInfo().size())
					{
						fmt::print("        Data Layer:\n");
					}
					else
					{
						fmt::print("        Hash Layer {:d}:\n", j);
					}
					fmt::print("          Offset:          0x{:x}\n", hash_hdr.getLayerInfo()[j].offset);
					fmt::print("          Size:            0x{:x}\n", hash_hdr.getLayerInfo()[j].size);
					fmt::print("          BlockSize:       0x{:x}\n", hash_hdr.getLayerInfo()[j].block_size);
				}
				for (size_t j = 0; j < hash_hdr.getMasterHashList().size(); j++)
				{
					fmt::print("        Master Hash {:d}:\n", j);
					fmt::print("          {:s}\n", tc::cli::FormatUtil::formatBytesAsString(hash_hdr.getMasterHashList()[j].data(), 0x10, true, ""));
					fmt::print("          {:s}\n", tc::cli::FormatUtil::formatBytesAsString(hash_hdr.getMasterHashList()[j].data()+0x10, 0x10, true, ""));
				}
			}
			else if (info.hash_type == pie::hac::nca::HashType_HierarchicalSha256)
			{
				auto hash_hdr = info.hierarchicalsha256_hdr;
				fmt::print("      HierarchicalSha256 Header:\n");
				fmt::print("        Master Hash:\n");
				fmt::print("          {:s}\n", tc::cli::FormatUtil::formatBytesAsString(hash_hdr.getMasterHash().data(), 0x10, true, ""));
				fmt::print("          {:s}\n", tc::cli::FormatUtil::formatBytesAsString(hash_hdr.getMasterHash().data()+0x10, 0x10, true, ""));
				fmt::print("        HashBlockSize:     0x{:x}\n", hash_hdr.getHashBlockSize());
				for (size_t j = 0; j < hash_hdr.getLayerInfo().size(); j++)
				{
					if (j+1 == hash_hdr.getLayerInfo().size())
					{
						fmt::print("        Data Layer:\n");
					}
					else
					{
						fmt::print("        Hash Layer {:d}:\n", j);
					}
					fmt::print("          Offset:          0x{:x}\n", hash_hdr.getLayerInfo()[j].offset);
					fmt::print("          Size:            0x{:x}\n", hash_hdr.getLayerInfo()[j].size);
				}
			}
		}
	}
}


void nstool::NcaProcess::processPartitions()
{
	mNca->processPartitions();


	std::shared_ptr<tc::io::IFileSystem> nca_fs = mNca->getFileSystem();

	mFsProcess.setInputFileSystem(nca_fs);
	mFsProcess.setFsFormatName("ContentArchive");
	mFsProcess.setFsRootLabel(getContentTypeForMountStr(mNca->getHeader().getContentType()));
	mFsProcess.process();
}

std::string nstool::NcaProcess::getContentTypeForMountStr(pie::hac::nca::ContentType cont_type) const
{
	std::string str;

	switch (cont_type)
	{
		case (pie::hac::nca::ContentType_Program):
			str = "program";
			break;
		case (pie::hac::nca::ContentType_Meta):
			str = "meta";
			break;
		case (pie::hac::nca::ContentType_Control):
			str = "control";
			break;
		case (pie::hac::nca::ContentType_Manual):
			str = "manual";
			break;
		case (pie::hac::nca::ContentType_Data):
			str = "data";
			break;
		case (pie::hac::nca::ContentType_PublicData):
			str = "publicdata";
			break;
		default:
			str = "";
			break;
	}

	return str;
}