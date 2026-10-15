package vision

import (
	"context"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/llm"

	"github.com/cloudwego/eino/schema"
)

// 真实多模态链路测试（默认跳过，需显式提供端点与凭据）：
//
//	CSAI_LIVE_CLAUDE_BASE_URL=https://api.stepfun.com/step_plan \
//	CSAI_LIVE_CLAUDE_API_KEY=*** \
//	CSAI_LIVE_CLAUDE_MODEL=step-5-preview \
//	go test ./internal/vision/ -run TestLive -v -timeout 10m
//
// 断言方式是「读图答题」而不是「接口 200」：图形与颜色每轮随机生成，只有真正看到图才能答对，
// 因此能区分「接口接受了图片字段」与「模型真的看懂了图」。
//
// 放在 vision 包是因为它同时能覆盖两条真实链路（vision 依赖 llm，反之不成立）：
//   - 原生直发：llm.NewClaudeAgenticModel + UserInputImage（supports_vision 走的路径）
//   - 旁路识图：vision.Client.Analyze（analyze_image 走的路径）
func TestLiveClaudeVisionReadsSyntheticImage(t *testing.T) {
	base, key, model := liveClaudeEnv(t)
	topColor, topShape, bottomColor, bottomShape, imgPath := writeSyntheticShapeImage(t)
	question := "这是一张 2x2 分区的图。不要输出思考过程，直接回答两行：第一行「左上：<颜色><形状>」，第二行「右下：<颜色><形状>」。"
	wantTop, wantBottom := topColor+topShape, bottomColor+bottomShape

	t.Run("native agentic image input", func(t *testing.T) {
		mdl, err := llm.NewClaudeAgenticModel(context.Background(), config.OpenAIConfig{
			Provider: "claude",
			APIKey:   key,
			BaseURL:  base,
			Model:    model,
		}, nil, 4096, nil) // 推理型模型会先输出 thinking，需要留足 token 才能出正文
		if err != nil {
			t.Fatalf("claude agentic model: %v", err)
		}
		native, err := PrepareNativeImage(imgPath)
		if err != nil {
			t.Fatalf("prepare native image: %v", err)
		}
		start := time.Now()
		resp, err := mdl.Generate(context.Background(), []*schema.AgenticMessage{{
			Role: schema.AgenticRoleTypeUser,
			ContentBlocks: []*schema.ContentBlock{
				schema.NewContentBlock(&schema.UserInputText{Text: question}),
				schema.NewContentBlock(&schema.UserInputImage{
					Base64Data: native.Base64,
					MIMEType:   native.MIMEType,
					Detail:     schema.ImageURLDetailAuto,
				}),
			},
		}})
		if err != nil {
			t.Fatalf("live generate failed (%s / %s): %v", base, model, err)
		}
		content, _ := llm.AgenticText(resp)
		t.Logf("live reply in %s: %s", time.Since(start).Round(time.Millisecond), content)
		assertQuadrants(t, "原生图片直发", content, wantTop, wantBottom, topColor, bottomColor, topShape, bottomShape)
	})

	t.Run("analyze_image client", func(t *testing.T) {
		client := NewClient(config.VisionConfig{
			Enabled:  true,
			Provider: "claude",
			APIKey:   key,
			BaseURL:  base,
			Model:    model,
		}, config.OpenAIConfig{})
		payload, _, err := PreprocessImageFile(imgPath, PreprocessOptions{
			MaxImageBytes:            5 << 20,
			MaxDimension:             2048,
			JPEGQuality:              82,
			MaxPayloadBytes:          512 << 10,
			SkipPreprocessBelowBytes: 2 << 20,
		})
		if err != nil {
			t.Fatalf("prepare image: %v", err)
		}
		start := time.Now()
		reply, err := client.Analyze(context.Background(), payload, question)
		if err != nil {
			t.Fatalf("live vision analyze failed (%s / %s): %v", base, model, err)
		}
		t.Logf("live vision reply in %s: %s", time.Since(start).Round(time.Millisecond), reply)
		assertQuadrants(t, "旁路识图", reply, wantTop, wantBottom, topColor, bottomColor, topShape, bottomShape)
	})
}

// assertQuadrants 要求两个象限的「颜色」与「形状」都出现在回答里：
// 只答一个象限、或颜色/形状说错，都必须失败——这是「模型真的看到图」的最小证据。
func assertQuadrants(t *testing.T, path, reply, wantTop, wantBottom, topColor, bottomColor, topShape, bottomShape string) {
	t.Helper()
	for _, want := range []string{topColor, bottomColor, topShape, bottomShape} {
		if !strings.Contains(reply, want) {
			t.Fatalf("%s 未正确读图：回答缺少 %q（want %s / %s），got %q", path, want, wantTop, wantBottom, reply)
		}
	}
}

func liveClaudeEnv(t *testing.T) (base, key, model string) {
	t.Helper()
	base = strings.TrimSpace(os.Getenv("CSAI_LIVE_CLAUDE_BASE_URL"))
	key = strings.TrimSpace(os.Getenv("CSAI_LIVE_CLAUDE_API_KEY"))
	model = strings.TrimSpace(os.Getenv("CSAI_LIVE_CLAUDE_MODEL"))
	if base == "" || key == "" || model == "" {
		t.Skip("live multimodal test skipped: set CSAI_LIVE_CLAUDE_BASE_URL / CSAI_LIVE_CLAUDE_API_KEY / CSAI_LIVE_CLAUDE_MODEL")
	}
	return base, key, model
}

// writeSyntheticShapeImage 生成随机图形图：左上与右下各一个随机颜色/形状，其余留白。
func writeSyntheticShapeImage(t *testing.T) (topColor, topShape, bottomColor, bottomShape, path string) {
	t.Helper()
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	type shape struct {
		name string
		draw func(img *image.RGBA, rect image.Rectangle, c color.RGBA)
	}
	type palette struct {
		name string
		rgba color.RGBA
	}
	colors := []palette{
		{"红色", color.RGBA{R: 220, A: 255}},
		{"绿色", color.RGBA{G: 180, A: 255}},
		{"蓝色", color.RGBA{B: 230, A: 255}},
		{"黄色", color.RGBA{R: 240, G: 210, A: 255}},
	}
	shapes := []shape{
		{"圆形", func(img *image.RGBA, rect image.Rectangle, c color.RGBA) {
			cx, cy := float64(rect.Min.X+rect.Dx()/2), float64(rect.Min.Y+rect.Dy()/2)
			edge := rect.Dx()
			if rect.Dy() < edge {
				edge = rect.Dy()
			}
			r := float64(edge) / 2 * 0.82
			for y := rect.Min.Y; y < rect.Max.Y; y++ {
				for x := rect.Min.X; x < rect.Max.X; x++ {
					dx, dy := float64(x)-cx, float64(y)-cy
					if dx*dx+dy*dy <= r*r {
						img.Set(x, y, c)
					}
				}
			}
		}},
		{"方形", func(img *image.RGBA, rect image.Rectangle, c color.RGBA) {
			draw.Draw(img, rect.Inset(rect.Dx()/10), &image.Uniform{C: c}, image.Point{}, draw.Src)
		}},
	}

	const size = 512
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	draw.Draw(img, img.Bounds(), &image.Uniform{C: color.White}, image.Point{}, draw.Src)

	top, topDef := colors[rng.Intn(len(colors))], shapes[rng.Intn(len(shapes))]
	bottom := colors[rng.Intn(len(colors))]
	for bottom.name == top.name { // 两象限颜色必须不同：撞色会让「只答对一半」也蒙对
		bottom = colors[rng.Intn(len(colors))]
	}
	bottomDef := shapes[rng.Intn(len(shapes))]
	topDef.draw(img, image.Rect(40, 40, 240, 240), top.rgba)
	bottomDef.draw(img, image.Rect(272, 272, 472, 472), bottom.rgba)

	path = fmt.Sprintf("%s/live-shapes-%d.png", t.TempDir(), time.Now().UnixNano())
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create synthetic image: %v", err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		t.Fatalf("encode synthetic image: %v", err)
	}
	return top.name, topDef.name, bottom.name, bottomDef.name, path
}
