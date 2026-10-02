import React from 'react';

const SocHeader = ({
  onToggleSidebar,
  onUploadPcap,
  uploading = false,
  onIngestTestbed,
  ingesting = false,
  activeJobId = null,
  onDownloadReport,
  isRealData = false,
  onOpenRemediation,
}) => {
  const fileInputRef = React.useRef(null);

  const handleFileChange = (e) => {
    const file = e.target.files?.[0];
    if (file && onUploadPcap) {
      onUploadPcap(file);
      // reset so same file can be re-uploaded
      e.target.value = '';
    }
  };

  return (
    <header className="h-[72px] bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl px-4 lg:px-6 flex items-center justify-between shadow-xs transition-colors">
      {/* Left: Mobile hamburger & Title */}
      <div className="flex items-center space-x-3">
        <button
          onClick={onToggleSidebar}
          className="lg:hidden p-2 rounded-lg text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-[#23252A] cursor-pointer"
          aria-label="Toggle Menu"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 6h16M4 12h16M4 18h16" />
          </svg>
        </button>
        <h1 className="text-sm font-bold text-gray-800 dark:text-gray-200 hidden sm:inline">
          SOC Dashboard
        </h1>
      </div>

      {/* Right: Actions */}
      <div className="flex items-center space-x-2.5 sm:space-x-3">
        <input
          type="file"
          ref={fileInputRef}
          onChange={handleFileChange}
          accept=".pcap,.pcapng,.cap"
          className="hidden"
        />

        {/* Auto-Ingest Testbed */}
        {onIngestTestbed && (
          <button
            onClick={onIngestTestbed}
            disabled={uploading || ingesting}
            className={`inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-bold border transition-all cursor-pointer shadow-xs ${
              ingesting
                ? 'bg-purple-500/20 text-purple-400 border-purple-500/30 animate-pulse'
                : 'bg-purple-600 hover:bg-purple-700 text-white border-purple-600'
            }`}
            title="Auto-ingest captures from the testbed"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
                d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            <span>{ingesting ? 'Ingesting…' : 'Ingest Testbed'}</span>
          </button>
        )}

        {/* Upload PCAP */}
        <button
          onClick={() => fileInputRef.current?.click()}
          disabled={uploading || ingesting}
          className={`inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-bold border transition-all cursor-pointer shadow-xs ${
            uploading
              ? 'bg-blue-500/20 text-blue-400 border-blue-500/30 animate-pulse'
              : 'bg-blue-600 hover:bg-blue-700 text-white border-blue-600'
          }`}
          title="Upload a PCAP/PCAPNG capture for analysis"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
              d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
          </svg>
          <span>{uploading ? 'Analysing…' : isRealData ? 'Upload New PCAP' : 'Upload PCAP'}</span>
        </button>

        {/* AI Hardening */}
        {onOpenRemediation && (
          <button
            onClick={onOpenRemediation}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-bold bg-amber-500/10 hover:bg-amber-500/20 text-amber-600 dark:text-amber-400 border border-amber-500/30 transition-colors cursor-pointer"
            title="Generate AI-hardened IPsec configuration"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
                d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
            <span>AI Hardening</span>
          </button>
        )}

        {/* PDF Report — only when a job exists */}
        {activeJobId && onDownloadReport && (
          <button
            onClick={onDownloadReport}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-bold bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30 transition-colors cursor-pointer"
            title="Download PDF Assessment Report"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
                d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            <span>PDF Report</span>
          </button>
        )}
      </div>
    </header>
  );
};

export default SocHeader;
