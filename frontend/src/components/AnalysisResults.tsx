import React from 'react';
import type { AnalysisResult } from '../types/analysis';

interface AnalysisResultsProps {
  result: AnalysisResult;
  onReset: () => void;
}

export const AnalysisResults: React.FC<AnalysisResultsProps> = ({ result, onReset }) => {
  const getThreatLevel = () => {
    if (result.yaraMatched) return 'high';
    if (result.mlRiskScore > 0.7) return 'high';
    if (result.mlRiskScore > 0.4) return 'medium';
    return 'low';
  };

  const threatLevel = getThreatLevel();
  const threatColors = {
    high: 'bg-red-100 border-red-300 text-red-800',
    medium: 'bg-yellow-100 border-yellow-300 text-yellow-800',
    low: 'bg-green-100 border-green-300 text-green-800',
  };

  return (
    <div className="w-full max-w-6xl mx-auto">
      <div className="mb-6 flex justify-between items-center">
        <h2 className="text-2xl font-bold text-gray-800">Analysis Results</h2>
        <button
          onClick={onReset}
          className="px-4 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700 transition-colors"
        >
          Analyze Another File
        </button>
      </div>

      <div className="space-y-6">
        <div className="bg-white rounded-lg shadow-md p-6">
          <h3 className="text-lg font-semibold mb-4 text-gray-800">File Information</h3>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <p className="text-sm text-gray-600">Filename</p>
              <p className="font-medium text-gray-900">{result.filename}</p>
            </div>
            <div>
              <p className="text-sm text-gray-600">Binary ID</p>
              <p className="font-mono text-sm text-gray-900">{result.binaryId}</p>
            </div>
            <div>
              <p className="text-sm text-gray-600">Classification</p>
              <span className={`inline-block px-3 py-1 rounded-full text-sm font-medium ${threatColors[threatLevel]}`}>
                {result.classification.toUpperCase()}
              </span>
            </div>
            <div>
              <p className="text-sm text-gray-600">ML Risk Score</p>
              <p className="font-medium text-gray-900">{result.mlRiskScore.toFixed(2)}</p>
            </div>
          </div>
        </div>

        {result.yaraMatched && result.matchedRules.length > 0 && (
          <div className="bg-white rounded-lg shadow-md p-6 border-l-4 border-red-500">
            <h3 className="text-lg font-semibold mb-4 text-red-700">YARA Rule Matches</h3>
            <div className="flex flex-wrap gap-2">
              {result.matchedRules.map((rule, index) => (
                <span
                  key={index}
                  className="px-3 py-1 bg-red-100 text-red-800 rounded-md text-sm font-medium"
                >
                  {rule}
                </span>
              ))}
            </div>
          </div>
        )}

        {result.machineType && (
          <div className="bg-white rounded-lg shadow-md p-6">
            <h3 className="text-lg font-semibold mb-4 text-gray-800">PE Header Information</h3>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-sm text-gray-600">Machine Type</p>
                <p className="font-medium text-gray-900">{result.machineType}</p>
              </div>
              <div>
                <p className="text-sm text-gray-600">Subsystem</p>
                <p className="font-medium text-gray-900">{result.subsystem || 'N/A'}</p>
              </div>
              <div>
                <p className="text-sm text-gray-600">Entry Point</p>
                <p className="font-mono text-sm text-gray-900">
                  {result.entryPoint ? `0x${result.entryPoint.toString(16).toUpperCase()}` : 'N/A'}
                </p>
              </div>
              <div>
                <p className="text-sm text-gray-600">Image Base</p>
                <p className="font-mono text-sm text-gray-900">
                  {result.imageBase ? `0x${result.imageBase.toString(16).toUpperCase()}` : 'N/A'}
                </p>
              </div>
              {result.packed !== undefined && (
                <div>
                  <p className="text-sm text-gray-600">Packed</p>
                  <span className={`inline-block px-3 py-1 rounded-full text-sm font-medium ${
                    result.packed ? 'bg-orange-100 text-orange-800' : 'bg-blue-100 text-blue-800'
                  }`}>
                    {result.packed ? 'Yes' : 'No'}
                  </span>
                </div>
              )}
            </div>
          </div>
        )}

        {result.sections && result.sections.length > 0 && (
          <div className="bg-white rounded-lg shadow-md p-6">
            <h3 className="text-lg font-semibold mb-4 text-gray-800">PE Sections</h3>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Name
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      RVA
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Virtual Size
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Raw Size
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Entropy
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Characteristics
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {result.sections.map((section, index) => (
                    <tr key={index} className={section.entropy > 7 ? 'bg-red-50' : ''}>
                      <td className="px-4 py-3 whitespace-nowrap text-sm font-medium text-gray-900">
                        {section.name}
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-500 font-mono">
                        0x{section.rva.toString(16).toUpperCase()}
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-500">
                        {section.virtualSize.toLocaleString()} bytes
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-500">
                        {section.rawSize.toLocaleString()} bytes
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-500">
                        <span className={`font-medium ${section.entropy > 7 ? 'text-red-600' : ''}`}>
                          {section.entropy.toFixed(3)}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-500 max-w-xs truncate" title={section.characteristics}>
                        {section.characteristics}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {result.sections.some(s => s.entropy > 7) && (
              <p className="mt-3 text-sm text-orange-600">
                High entropy sections (red highlight) may indicate packed or encrypted code
              </p>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
