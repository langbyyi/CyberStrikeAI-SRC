package project

import "strings"

// VisionImageSectionMarker 图片分析 section 标题（与 AppendVisionImageAnalysisIfReady 注入一致）。
const VisionImageSectionMarker = "## 图片分析"

// NativeImageInputSectionMarker 主模型原生多模态时的图片输入 section 标题。
const NativeImageInputSectionMarker = "## 图片输入"

// VisionImageAnalysisSection 单/多代理共用的图片分析提示（analyze_image；上下文仅保留文字摘要）。
func VisionImageAnalysisSection() string {
	var b strings.Builder
	b.WriteString(VisionImageSectionMarker)
	b.WriteString("\n\n")
	b.WriteString("- 遇到图片文件（截图、验证码、登录页、报告配图）时，若存在工具 analyze_image，请传入服务器上的文件路径进行分析。\n")
	b.WriteString("- 不要对二进制图片使用 read_file 指望理解内容；用户消息中「📎 xxx.png: /path」即为可传给 analyze_image 的路径。\n")
	b.WriteString("- 验证码类：若已从页面或接口保存为本地图片（如 captcha.png），用 analyze_image，question 写明「只输出验证码字符」；识别失败则刷新验证码后重新保存再识；复杂滑块/行为验证码勿指望单次识图成功。\n")
	b.WriteString("- 委派子代理时，若子任务含验证码/截图识读，在 task description 中写明图片路径与期望输出格式。\n")
	return b.String()
}

// NativeImageInputSection 主模型可直接读图（多模态）时的提示。
//
// 读图的统一入口是 read_file：框架的多模态 read_file 会把图片作为图片输入返回给模型，
// 因此这里不再引导 analyze_image 旁路识图（那是纯文本主模型的兜底，见 VisionImageAnalysisSection）。
func NativeImageInputSection() string {
	var b strings.Builder
	b.WriteString(NativeImageInputSectionMarker)
	b.WriteString("\n\n")
	b.WriteString("- 当前主模型支持直接读图：用户上传的图片已作为图片输入随本轮消息给出，直接看图回答，**不要**再说「看不到图片」。\n")
	b.WriteString("- 磁盘上的图片（工具截图、接口下载的验证码、报告配图）直接用 read_file 读取：图片会作为图片输入返回给你；不要用 execute/curl 去解析二进制图片。\n")
	b.WriteString("- 图片只进入被读取/上传的那一轮上下文；后续轮次若还需参考，重新 read_file 同一路径即可（路径已写在历史消息里）。\n")
	b.WriteString("- 委派子代理时，子代理看不到父对话已附带的图片：在 task description 中写明图片路径，子代理自行 read_file。\n")
	b.WriteString("- 复杂验证码（滑块/点选/强噪点）单次识读可能失败：换图重取或改用专用工具（如 ddddocr），不要对同一张图连续空转。\n")
	return b.String()
}

// AppendVisionImageAnalysisIfReady 追加图片相关提示：
//   - nativeVision：主模型可直接读图（本轮附件已作为图片输入直发）；
//   - visionReady：analyze_image 工具可用（磁盘图片旁路识图）。
//
// 两者都为假时不追加任何内容。
func AppendVisionImageAnalysisIfReady(base string, visionReady bool, nativeVision bool) string {
	switch {
	case nativeVision:
		// 原生多模态：读图走 read_file，不再引导 analyze_image 旁路
		return AppendSystemPromptBlock(base, NativeImageInputSection())
	case visionReady:
		// 纯文本主模型：磁盘图片只能旁路识图（兼容路径）
		return AppendSystemPromptBlock(base, VisionImageAnalysisSection())
	default:
		return base
	}
}
